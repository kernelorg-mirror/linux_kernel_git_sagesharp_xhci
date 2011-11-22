/*
 * USB Attached SCSI
 * Note that this is not the same as the USB Mass Storage driver
 *
 * Copyright Matthew Wilcox for Intel Corp, 2010
 * Copyright Sarah Sharp for Intel Corp, 2010
 *
 * Distributed under the terms of the GNU GPL, version two.
 */

#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/srcu.h>
#include <linux/usb.h>
#include <linux/usb/storage.h>

#include <scsi/scsi.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

/* Common header for all IUs */
struct iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
};

enum {
	IU_ID_COMMAND		= 0x01,
	IU_ID_STATUS		= 0x03,
	IU_ID_RESPONSE		= 0x04,
	IU_ID_TASK_MGMT		= 0x05,
	IU_ID_READ_READY	= 0x06,
	IU_ID_WRITE_READY	= 0x07,
};

enum {
	IU_FUNC_ABORT_TASK	= 0x01,
	IU_FUNC_ABORT_TASK_SET	= 0x02,
	IU_FUNC_CLEAR_TASK_SET	= 0x04,
	IU_FUNC_LOG_UNIT_RESET	= 0x08,
	IU_FUNC_I_T_NEXUS_RESET	= 0x10,
	IU_FUNC_CLEAR_ACA	= 0x40,
	IU_FUNC_QUERY_TASK	= 0x80,
	IU_FUNC_QUERY_TASK_SET	= 0x81,
	IU_FUNC_QUERY_ASYNC_EVT	= 0x82,
};

struct task_iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__u8 function;
	__u8 rsvd5;
	__be16 managed_tag;
	struct scsi_lun lun;
};

struct command_iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__u8 prio_attr;
	__u8 rsvd5;
	__u8 len;
	__u8 rsvd7;
	struct scsi_lun lun;
	__u8 cdb[16];	/* XXX: Overflow-checking tools may misunderstand */
};

/*
 * Also used for the Read Ready and Write Ready IUs since they have the
 * same first four bytes
 */
struct sense_iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__be16 status_qual;
	__u8 status;
	__u8 rsvd7[7];
	__be16 len;
	__u8 sense[SCSI_SENSE_BUFFERSIZE];
};

/*
 * The r00-r01c specs define this version of the SENSE IU data structure.
 * It's still in use by several different firmware releases.
 */
struct sense_iu_old {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__be16 len;
	__u8 status;
	__u8 service_response;
	__u8 sense[SCSI_SENSE_BUFFERSIZE];
};

struct response_iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__u8 info[3];
	__u8 code;
};

#define UAS_TASK_COMPLETE	0x00
#define UAS_TASK_SUCCESS	0x08

enum {
	CMD_PIPE_ID		= 1,
	STATUS_PIPE_ID		= 2,
	DATA_IN_PIPE_ID		= 3,
	DATA_OUT_PIPE_ID	= 4,

	UAS_SIMPLE_TAG		= 0,
	UAS_HEAD_TAG		= 1,
	UAS_ORDERED_TAG		= 2,
	UAS_ACA			= 4,
};

struct uas_dev_info {
	struct usb_interface *intf;
	struct usb_device *udev;
	struct srcu_struct *srcu;
	int qdepth;
	unsigned cmd_pipe, status_pipe, data_in_pipe, data_out_pipe;
	unsigned use_streams:1;
	unsigned uas_sense_old:1;
	atomic_t resetting;
	/* Array of anchors, one for each tag. */
	struct usb_anchor *anchors;
};

enum {
	ALLOC_STATUS_URB	= (1 << 0),
	SUBMIT_STATUS_URB	= (1 << 1),
	ALLOC_DATA_IN_URB	= (1 << 2),
	SUBMIT_DATA_IN_URB	= (1 << 3),
	ALLOC_DATA_OUT_URB	= (1 << 4),
	SUBMIT_DATA_OUT_URB	= (1 << 5),
	ALLOC_CMD_URB		= (1 << 6),
	SUBMIT_CMD_URB		= (1 << 7),
};

/* Overrides scsi_pointer */
struct uas_cmd_info {
	unsigned int state;
	unsigned int stream;
	struct urb *cmd_urb;
	struct urb *status_urb;
	struct urb *data_in_urb;
	struct urb *data_out_urb;
	struct list_head list;
};

/* I hate forward declarations, but I actually have a loop */
static int uas_submit_urbs(struct scsi_cmnd *cmnd,
				struct uas_dev_info *devinfo, gfp_t gfp);
static void uas_do_work(struct work_struct *work);

static DECLARE_WORK(uas_work, uas_do_work);
static DEFINE_SPINLOCK(uas_work_lock);
static LIST_HEAD(uas_work_list);

static void uas_do_work(struct work_struct *work)
{
	struct uas_cmd_info *cmdinfo;
	struct uas_cmd_info *temp;
	struct list_head list;
	int err;

	spin_lock_irq(&uas_work_lock);
	list_replace_init(&uas_work_list, &list);
	spin_unlock_irq(&uas_work_lock);

	spin_lock_irq(&uas_work_lock);
	list_for_each_entry_safe(cmdinfo, temp, &list, list) {
		struct scsi_pointer *scp = (void *)cmdinfo;
		struct scsi_cmnd *cmnd = container_of(scp,
							struct scsi_cmnd, SCp);
		err = uas_submit_urbs(cmnd, cmnd->device->hostdata, GFP_NOIO);
		list_del_init(&cmdinfo->list);
		if (err) {
			list_add_tail(&cmdinfo->list, &uas_work_list);
			schedule_work(&uas_work);
		}
	}
	spin_unlock_irq(&uas_work_lock);
}

static void uas_sense(struct urb *urb, struct scsi_cmnd *cmnd)
{
	struct sense_iu *sense_iu = urb->transfer_buffer;
	struct scsi_device *sdev = cmnd->device;

	if (urb->actual_length > 16) {
		unsigned len = be16_to_cpup(&sense_iu->len);
		if (len + 16 != urb->actual_length) {
			int newlen = min(len + 16, urb->actual_length) - 16;
			if (newlen < 0)
				newlen = 0;
			sdev_printk(KERN_INFO, sdev, "%s: urb length %d "
				"disagrees with IU sense data length %d, "
				"using %d bytes of sense data\n", __func__,
					urb->actual_length, len, newlen);
			len = newlen;
		}
		memcpy(cmnd->sense_buffer, sense_iu->sense, len);
	}

	cmnd->result = sense_iu->status;
	if (sdev->current_cmnd)
		sdev->current_cmnd = NULL;
	cmnd->scsi_done(cmnd);
	usb_free_urb(urb);
}

static void uas_sense_old(struct urb *urb, struct scsi_cmnd *cmnd)
{
	struct sense_iu_old *sense_iu = urb->transfer_buffer;
	struct scsi_device *sdev = cmnd->device;

	if (urb->actual_length > 8) {
		unsigned len = be16_to_cpup(&sense_iu->len) - 2;
		if (len + 8 != urb->actual_length) {
			int newlen = min(len + 8, urb->actual_length) - 8;
			if (newlen < 0)
				newlen = 0;
			sdev_printk(KERN_INFO, sdev, "%s: urb length %d "
				"disagrees with IU sense data length %d, "
				"using %d bytes of sense data\n", __func__,
					urb->actual_length, len, newlen);
			len = newlen;
		}
		memcpy(cmnd->sense_buffer, sense_iu->sense, len);
	}

	cmnd->result = sense_iu->status;
	if (sdev->current_cmnd)
		sdev->current_cmnd = NULL;
	cmnd->scsi_done(cmnd);
	usb_free_urb(urb);
}

static int uas_xfer_data(struct urb *urb, struct scsi_cmnd *cmnd,
		struct uas_dev_info *devinfo, unsigned direction)
{
	struct uas_cmd_info *cmdinfo = (void *)&cmnd->SCp;
	int err, srcu_idx;

	srcu_idx = srcu_read_lock(devinfo->srcu);
	if (atomic_read(&devinfo->resetting)) {
		srcu_read_unlock(devinfo->srcu, srcu_idx);
		return -ENODEV;
	}

	cmdinfo->state = direction | SUBMIT_STATUS_URB;
	err = uas_submit_urbs(cmnd, cmnd->device->hostdata, GFP_ATOMIC);
	if (err) {
		spin_lock(&uas_work_lock);
		list_add_tail(&cmdinfo->list, &uas_work_list);
		spin_unlock(&uas_work_lock);
		schedule_work(&uas_work);
	}
	srcu_read_unlock(devinfo->srcu, srcu_idx);
	return 0;
}

static void uas_stat_cmplt(struct urb *urb)
{
	struct iu *iu = urb->transfer_buffer;
	struct scsi_device *sdev = urb->context;
	struct uas_dev_info *devinfo = sdev->hostdata;
	struct scsi_cmnd *cmnd;
	u16 tag;
	int ret = 0;

	tag = be16_to_cpup(&iu->tag) - 1;
	if (sdev->current_cmnd)
		cmnd = sdev->current_cmnd;
	else
		cmnd = scsi_find_tag(sdev, tag);
	if (!cmnd) {
		usb_free_urb(urb);
		return;
	}

	/* If the URB was canceled (by either SCSI layer or reset device). */
	if (urb->status == -ECONNRESET || urb->status == -ENOENT)
		goto task_abort;
	/* FIXME: handle other URB error cases too */
	if (urb->status) {
		dev_err(&urb->dev->dev, "URB BAD STATUS %d\n", urb->status);
		usb_free_urb(urb);
		return;
	}

	switch (iu->iu_id) {
	case IU_ID_STATUS:
		if (urb->actual_length < 16)
			devinfo->uas_sense_old = 1;
		if (devinfo->uas_sense_old)
			uas_sense_old(urb, cmnd);
		else
			uas_sense(urb, cmnd);
		break;
	case IU_ID_READ_READY:
		ret = uas_xfer_data(urb, cmnd, devinfo, SUBMIT_DATA_IN_URB);
		break;
	case IU_ID_WRITE_READY:
		ret = uas_xfer_data(urb, cmnd, devinfo, SUBMIT_DATA_OUT_URB);
		break;
	default:
		scmd_printk(KERN_ERR, cmnd,
			"Bogus IU (%d) received on status pipe\n", iu->iu_id);
	}
	if (!ret)
		return;

task_abort:
	cmnd->result = SAM_STAT_TASK_ABORTED;
	if (sdev->current_cmnd)
		sdev->current_cmnd = NULL;
	cmnd->scsi_done(cmnd);
	usb_free_urb(urb);
	return;
}

static void uas_data_cmplt(struct urb *urb)
{
	struct scsi_data_buffer *sdb = urb->context;
	sdb->resid = sdb->length - urb->actual_length;
	usb_free_urb(urb);
}

static struct urb *uas_alloc_data_urb(struct uas_dev_info *devinfo, gfp_t gfp,
				unsigned int pipe, u16 stream_id,
				struct scsi_data_buffer *sdb,
				enum dma_data_direction dir)
{
	struct usb_device *udev = devinfo->udev;
	struct urb *urb = usb_alloc_urb(0, gfp);

	if (!urb)
		goto out;
	usb_fill_bulk_urb(urb, udev, pipe, NULL, sdb->length, uas_data_cmplt,
									sdb);
	if (devinfo->use_streams)
		urb->stream_id = stream_id;
	urb->num_sgs = udev->bus->sg_tablesize ? sdb->table.nents : 0;
	urb->sg = sdb->table.sgl;
 out:
	return urb;
}

static struct urb *uas_alloc_sense_urb(struct uas_dev_info *devinfo, gfp_t gfp,
					struct scsi_cmnd *cmnd, u16 stream_id)
{
	struct usb_device *udev = devinfo->udev;
	struct urb *urb = usb_alloc_urb(0, gfp);
	struct sense_iu *iu;

	if (!urb)
		goto out;

	iu = kzalloc(sizeof(*iu), gfp);
	if (!iu)
		goto free;

	usb_fill_bulk_urb(urb, udev, devinfo->status_pipe, iu, sizeof(*iu),
						uas_stat_cmplt, cmnd->device);
	urb->stream_id = stream_id;
	urb->transfer_flags |= URB_FREE_BUFFER;
 out:
	return urb;
 free:
	usb_free_urb(urb);
	return NULL;
}

static struct urb *uas_alloc_cmd_urb(struct uas_dev_info *devinfo, gfp_t gfp,
					struct scsi_cmnd *cmnd, u16 stream_id)
{
	struct usb_device *udev = devinfo->udev;
	struct scsi_device *sdev = cmnd->device;
	struct urb *urb = usb_alloc_urb(0, gfp);
	struct command_iu *iu;
	int len;

	if (!urb)
		goto out;

	len = cmnd->cmd_len - 16;
	if (len < 0)
		len = 0;
	len = ALIGN(len, 4);
	iu = kzalloc(sizeof(*iu) + len, gfp);
	if (!iu)
		goto free;

	iu->iu_id = IU_ID_COMMAND;
	if (blk_rq_tagged(cmnd->request))
		iu->tag = cpu_to_be16(cmnd->request->tag + 1);
	else
		iu->tag = cpu_to_be16(1);
	iu->prio_attr = UAS_SIMPLE_TAG;
	iu->len = len;
	int_to_scsilun(sdev->lun, &iu->lun);
	memcpy(iu->cdb, cmnd->cmnd, cmnd->cmd_len);

	usb_fill_bulk_urb(urb, udev, devinfo->cmd_pipe, iu, sizeof(*iu) + len,
							usb_free_urb, NULL);
	urb->transfer_flags |= URB_FREE_BUFFER;
 out:
	return urb;
 free:
	usb_free_urb(urb);
	return NULL;
}

/*
 * Why should I request the Status IU before sending the Command IU?  Spec
 * says to, but also says the device may receive them in any order.  Seems
 * daft to me.
 */

static int uas_submit_urbs(struct scsi_cmnd *cmnd,
					struct uas_dev_info *devinfo, gfp_t gfp)
{
	struct uas_cmd_info *cmdinfo = (void *)&cmnd->SCp;
	struct usb_anchor *anchor;

	if (blk_rq_tagged(cmnd->request))
		anchor = &devinfo->anchors[cmnd->request->tag];
	else
		anchor = &devinfo->anchors[0];

	if (cmdinfo->state & ALLOC_STATUS_URB) {
		cmdinfo->status_urb = uas_alloc_sense_urb(devinfo, gfp, cmnd,
							  cmdinfo->stream);
		if (!cmdinfo->status_urb)
			return SCSI_MLQUEUE_DEVICE_BUSY;
		cmdinfo->state &= ~ALLOC_STATUS_URB;
	}

	if (cmdinfo->state & SUBMIT_STATUS_URB) {
		usb_anchor_urb(cmdinfo->status_urb, anchor);
		if (usb_submit_urb(cmdinfo->status_urb, gfp)) {
			scmd_printk(KERN_INFO, cmnd,
					"sense urb submission failure\n");
			usb_unanchor_urb(cmdinfo->status_urb);
			return SCSI_MLQUEUE_DEVICE_BUSY;
		}
		cmdinfo->state &= ~SUBMIT_STATUS_URB;
	}

	if (cmdinfo->state & ALLOC_DATA_IN_URB) {
		cmdinfo->data_in_urb = uas_alloc_data_urb(devinfo, gfp,
					devinfo->data_in_pipe, cmdinfo->stream,
					scsi_in(cmnd), DMA_FROM_DEVICE);
		if (!cmdinfo->data_in_urb)
			return SCSI_MLQUEUE_DEVICE_BUSY;
		cmdinfo->state &= ~ALLOC_DATA_IN_URB;
	}

	if (cmdinfo->state & SUBMIT_DATA_IN_URB) {
		usb_anchor_urb(cmdinfo->data_in_urb, anchor);
		if (usb_submit_urb(cmdinfo->data_in_urb, gfp)) {
			scmd_printk(KERN_INFO, cmnd,
					"data in urb submission failure\n");
			usb_unanchor_urb(cmdinfo->data_in_urb);
			return SCSI_MLQUEUE_DEVICE_BUSY;
		}
		cmdinfo->state &= ~SUBMIT_DATA_IN_URB;
	}

	if (cmdinfo->state & ALLOC_DATA_OUT_URB) {
		cmdinfo->data_out_urb = uas_alloc_data_urb(devinfo, gfp,
					devinfo->data_out_pipe, cmdinfo->stream,
					scsi_out(cmnd), DMA_TO_DEVICE);
		if (!cmdinfo->data_out_urb)
			return SCSI_MLQUEUE_DEVICE_BUSY;
		cmdinfo->state &= ~ALLOC_DATA_OUT_URB;
	}

	if (cmdinfo->state & SUBMIT_DATA_OUT_URB) {
		usb_anchor_urb(cmdinfo->data_out_urb, anchor);
		if (usb_submit_urb(cmdinfo->data_out_urb, gfp)) {
			scmd_printk(KERN_INFO, cmnd,
					"data out urb submission failure\n");
			usb_unanchor_urb(cmdinfo->data_out_urb);
			return SCSI_MLQUEUE_DEVICE_BUSY;
		}
		cmdinfo->state &= ~SUBMIT_DATA_OUT_URB;
	}

	if (cmdinfo->state & ALLOC_CMD_URB) {
		cmdinfo->cmd_urb = uas_alloc_cmd_urb(devinfo, gfp, cmnd,
							cmdinfo->stream);
		if (!cmdinfo->cmd_urb)
			return SCSI_MLQUEUE_DEVICE_BUSY;
		cmdinfo->state &= ~ALLOC_CMD_URB;
	}

	if (cmdinfo->state & SUBMIT_CMD_URB) {
		usb_anchor_urb(cmdinfo->cmd_urb, anchor);
		if (usb_submit_urb(cmdinfo->cmd_urb, gfp)) {
			scmd_printk(KERN_INFO, cmnd,
					"cmd urb submission failure\n");
			usb_unanchor_urb(cmdinfo->cmd_urb);
			return SCSI_MLQUEUE_DEVICE_BUSY;
		}
		cmdinfo->state &= ~SUBMIT_CMD_URB;
	}

	return 0;
}

static int uas_queuecommand_lck(struct scsi_cmnd *cmnd,
					void (*done)(struct scsi_cmnd *))
{
	struct scsi_device *sdev = cmnd->device;
	struct uas_dev_info *devinfo = sdev->hostdata;
	struct uas_cmd_info *cmdinfo = (void *)&cmnd->SCp;
	int err, srcu_idx;

	BUILD_BUG_ON(sizeof(struct uas_cmd_info) > sizeof(struct scsi_pointer));

	srcu_idx = srcu_read_lock(devinfo->srcu);
	if ((!cmdinfo->status_urb && sdev->current_cmnd) ||
			atomic_read(&devinfo->resetting)) {
		srcu_read_unlock(devinfo->srcu, srcu_idx);
		return SCSI_MLQUEUE_DEVICE_BUSY;
	}

	if (blk_rq_tagged(cmnd->request)) {
		cmdinfo->stream = cmnd->request->tag + 1;
	} else {
		sdev->current_cmnd = cmnd;
		cmdinfo->stream = 1;
	}

	cmnd->scsi_done = done;

	cmdinfo->state = ALLOC_STATUS_URB | SUBMIT_STATUS_URB |
			ALLOC_CMD_URB | SUBMIT_CMD_URB;
	INIT_LIST_HEAD(&cmdinfo->list);

	switch (cmnd->sc_data_direction) {
	case DMA_FROM_DEVICE:
		cmdinfo->state |= ALLOC_DATA_IN_URB | SUBMIT_DATA_IN_URB;
		break;
	case DMA_BIDIRECTIONAL:
		cmdinfo->state |= ALLOC_DATA_IN_URB | SUBMIT_DATA_IN_URB;
	case DMA_TO_DEVICE:
		cmdinfo->state |= ALLOC_DATA_OUT_URB | SUBMIT_DATA_OUT_URB;
	case DMA_NONE:
		break;
	}

	if (!devinfo->use_streams) {
		cmdinfo->state &= ~(SUBMIT_DATA_IN_URB | SUBMIT_DATA_OUT_URB);
		cmdinfo->stream = 0;
	}

	err = uas_submit_urbs(cmnd, devinfo, GFP_ATOMIC);
	if (err) {
		/* If we did nothing, give up now */
		if (cmdinfo->state & SUBMIT_STATUS_URB) {
			usb_free_urb(cmdinfo->status_urb);
			srcu_read_unlock(devinfo->srcu, srcu_idx);
			return SCSI_MLQUEUE_DEVICE_BUSY;
		}
		spin_lock(&uas_work_lock);
		list_add_tail(&cmdinfo->list, &uas_work_list);
		spin_unlock(&uas_work_lock);
		schedule_work(&uas_work);
	}

	srcu_read_unlock(devinfo->srcu, srcu_idx);
	return 0;
}

static DEF_SCSI_QCMD(uas_queuecommand)

static void uas_kill_tagged_urbs(struct usb_anchor *anchor,
		struct uas_cmd_info *cmdinfo)
{
	usb_kill_anchored_urbs(anchor);

	/* Free any URBs that weren't submitted. */
	if (cmdinfo->state & SUBMIT_STATUS_URB) {
		kfree(cmdinfo->status_urb->transfer_buffer);
		usb_free_urb(cmdinfo->status_urb);
	}
	if (cmdinfo->state & SUBMIT_DATA_IN_URB) {
		kfree(cmdinfo->data_in_urb->transfer_buffer);
		usb_free_urb(cmdinfo->data_in_urb);
	}
	if (cmdinfo->state & SUBMIT_DATA_OUT_URB) {
		kfree(cmdinfo->data_out_urb->transfer_buffer);
		usb_free_urb(cmdinfo->data_out_urb);
	}
	if (cmdinfo->state & SUBMIT_CMD_URB) {
		kfree(cmdinfo->cmd_urb->transfer_buffer);
		usb_free_urb(cmdinfo->cmd_urb);
	}
}

static int uas_issue_abort_task(struct scsi_cmnd *cmnd,
		struct scsi_device *sdev, struct uas_dev_info *devinfo)
{
	struct task_iu *tiu = NULL;
	struct response_iu *riu = NULL;
	struct urb *task_urb = NULL;
	struct urb *response_urb = NULL;
	int timeleft, ret;

	ret = -ENOMEM;
	task_urb = usb_alloc_urb(0, GFP_NOIO);
	if (!task_urb)
		goto out;
	tiu = kzalloc(sizeof(*tiu), GFP_NOIO);
	if (!tiu)
		goto out;
	response_urb = usb_alloc_urb(0, GFP_NOIO);
	if (!response_urb)
		goto out;
	riu = kzalloc(sizeof(*riu), GFP_NOIO);
	if (!riu)
		goto out;

	ret = -ETIMEDOUT;
	sdev_printk(KERN_INFO, sdev,
			"%s tag %d issuing ABORT TASK with tag %d\n",
			__func__, cmnd->request->tag, devinfo->qdepth);

	usb_fill_bulk_urb(response_urb, devinfo->udev, devinfo->status_pipe,
			riu, sizeof(*riu), usb_free_urb, cmnd->device);
	response_urb->stream_id = devinfo->qdepth;
	/* Don't set URB_FREE_BUFFER so we can read the response */

	if (usb_submit_urb(response_urb, GFP_NOIO))
		goto out;
	usb_anchor_urb(response_urb, &devinfo->anchors[devinfo->qdepth - 1]);
	response_urb = NULL;

	tiu->iu_id = IU_ID_TASK_MGMT;
	/* Use tag we reserved when we set scsi queue length short */
	tiu->tag = cpu_to_be16(devinfo->qdepth);
	tiu->function = IU_FUNC_ABORT_TASK;
	if (blk_rq_tagged(cmnd->request))
		tiu->managed_tag = cpu_to_be16(cmnd->request->tag + 1);
	else
		tiu->managed_tag = cpu_to_be16(1);
	int_to_scsilun(sdev->lun, &tiu->lun);
	usb_fill_bulk_urb(task_urb, devinfo->udev, devinfo->cmd_pipe, tiu,
			sizeof(*tiu), usb_free_urb, NULL);
	task_urb->transfer_flags |= URB_FREE_BUFFER;

	if (usb_submit_urb(task_urb, GFP_NOIO)) {
		usb_kill_anchored_urbs(&devinfo->anchors[devinfo->qdepth - 1]);
		goto out;
	}
	usb_anchor_urb(task_urb, &devinfo->anchors[devinfo->qdepth - 1]);
	task_urb = NULL;
	tiu = NULL;

	/* Wait a whole second for the ABORT TASK to complete */
	timeleft = usb_wait_anchor_empty_timeout(
			&devinfo->anchors[devinfo->qdepth - 1],
			1000);
	if (!timeleft) {
		sdev_printk(KERN_INFO, sdev,
				"%s tag %d ABORT TASK timed out\n",
				__func__, cmnd->request->tag);
		usb_kill_anchored_urbs(&devinfo->anchors[devinfo->qdepth - 1]);
		goto out;
	}

	if (be16_to_cpu(riu->code) != UAS_TASK_SUCCESS &&
			be16_to_cpu(riu->code) != UAS_TASK_COMPLETE) {
		sdev_printk(KERN_INFO, sdev,
				"%s tag %d ABORT TASK failed, code 0x%x\n",
				__func__, cmnd->request->tag,
				be16_to_cpu(riu->code));
	} else {
		sdev_printk(KERN_INFO, sdev, "%s tag %d ABORT TASK success\n",
				__func__, cmnd->request->tag);
		ret = 0;
	}

out:
	kfree(tiu);
	usb_free_urb(task_urb);
	kfree(riu);
	usb_free_urb(response_urb);
	return ret;
}

static int uas_eh_abort_handler(struct scsi_cmnd *cmnd)
{
	struct scsi_device *sdev = cmnd->device;
	struct uas_dev_info *devinfo = sdev->hostdata;
	struct uas_cmd_info *cmdinfo = (void *)&cmnd->SCp;
	int srcu_idx;

	sdev_printk(KERN_INFO, sdev, "%s tag %d\n", __func__,
							cmnd->request->tag);

	srcu_idx = srcu_read_lock(devinfo->srcu);
	if (atomic_read(&devinfo->resetting)) {
		srcu_read_unlock(devinfo->srcu, srcu_idx);
		return FAILED;
	}

	spin_lock_irq(&uas_work_lock);
	if (!list_empty(&cmdinfo->list))
		list_del_init(&cmdinfo->list);
	spin_unlock_irq(&uas_work_lock);

	/* Send ABORT TASK Task Management command if we sent the command IU.
	 * XXX: we don't know if the command IU didn't make it because of an
	 * error (like electrical noise), since the completion function is
	 * usb_free_urb.  FIXME later.
	 */
	if (!(cmdinfo->state & SUBMIT_CMD_URB)) {
		if (uas_issue_abort_task(cmnd, sdev, devinfo)) {
			srcu_read_unlock(devinfo->srcu, srcu_idx);
			return FAILED;
		}
	}

	if (blk_rq_tagged(cmnd->request))
		uas_kill_tagged_urbs(&devinfo->anchors[cmnd->request->tag], cmdinfo);
	else
		uas_kill_tagged_urbs(&devinfo->anchors[0], cmdinfo);

	srcu_read_unlock(devinfo->srcu, srcu_idx);
	return SUCCESS;
}

static int uas_eh_device_reset_handler(struct scsi_cmnd *cmnd)
{
	struct scsi_device *sdev = cmnd->device;
	sdev_printk(KERN_INFO, sdev, "%s tag %d\n", __func__,
							cmnd->request->tag);

/* XXX: Send LOGICAL UNIT RESET Task Management command */
	return FAILED;
}

static int uas_eh_target_reset_handler(struct scsi_cmnd *cmnd)
{
	struct scsi_device *sdev = cmnd->device;
	sdev_printk(KERN_INFO, sdev, "%s tag %d\n", __func__,
							cmnd->request->tag);

/* XXX: Can we reset just the one USB interface?
 * Would calling usb_set_interface() have the right effect?
 */
	return FAILED;
}

static int uas_eh_bus_reset_handler(struct scsi_cmnd *cmnd)
{
	struct scsi_device *sdev = cmnd->device;
	struct uas_dev_info *devinfo = sdev->hostdata;
	struct usb_device *udev = devinfo->udev;

	sdev_printk(KERN_INFO, sdev, "%s tag %d\n", __func__,
							cmnd->request->tag);

	if (usb_reset_device(udev))
		return SUCCESS;

	return FAILED;
}

static int uas_slave_alloc(struct scsi_device *sdev)
{
	sdev->hostdata = (void *)sdev->host->hostdata[0];
	return 0;
}

static int uas_slave_configure(struct scsi_device *sdev)
{
	struct uas_dev_info *devinfo = sdev->hostdata;
	scsi_set_tag_type(sdev, MSG_ORDERED_TAG);
	/* Tag 0 is reserved; reserve another for command abort task IU */
	scsi_activate_tcq(sdev, devinfo->qdepth - 2);
	return 0;
}

static struct scsi_host_template uas_host_template = {
	.module = THIS_MODULE,
	.name = "uas",
	.queuecommand = uas_queuecommand,
	.slave_alloc = uas_slave_alloc,
	.slave_configure = uas_slave_configure,
	.eh_abort_handler = uas_eh_abort_handler,
	.eh_device_reset_handler = uas_eh_device_reset_handler,
	.eh_target_reset_handler = uas_eh_target_reset_handler,
	.eh_bus_reset_handler = uas_eh_bus_reset_handler,
	.can_queue = 65536,	/* Is there a limit on the _host_ ? */
	.this_id = -1,
	.sg_tablesize = SG_NONE,
	.cmd_per_lun = 1,	/* until we override it */
	.skip_settle_delay = 1,
	.ordered_tag = 1,
};

static struct usb_device_id uas_usb_ids[] = {
	{ USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_BULK) },
	{ USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_UAS) },
	/* 0xaa is a prototype device I happen to have access to */
	{ USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, 0xaa) },
	{ }
};
MODULE_DEVICE_TABLE(usb, uas_usb_ids);

static int uas_is_interface(struct usb_host_interface *intf)
{
	return (intf->desc.bInterfaceClass == USB_CLASS_MASS_STORAGE &&
		intf->desc.bInterfaceSubClass == USB_SC_SCSI &&
		intf->desc.bInterfaceProtocol == USB_PR_UAS);
}

static int uas_switch_interface(struct usb_device *udev,
						struct usb_interface *intf)
{
	int i;

	if (uas_is_interface(intf->cur_altsetting))
		return 0;

	for (i = 0; i < intf->num_altsetting; i++) {
		struct usb_host_interface *alt = &intf->altsetting[i];
		if (alt == intf->cur_altsetting)
			continue;
		if (uas_is_interface(alt))
			return usb_set_interface(udev,
						alt->desc.bInterfaceNumber,
						alt->desc.bAlternateSetting);
	}

	return -ENODEV;
}

static void uas_configure_endpoints(struct uas_dev_info *devinfo)
{
	struct usb_host_endpoint *eps[4] = { };
	struct usb_interface *intf = devinfo->intf;
	struct usb_device *udev = devinfo->udev;
	struct usb_host_endpoint *endpoint = intf->cur_altsetting->endpoint;
	unsigned i, n_endpoints = intf->cur_altsetting->desc.bNumEndpoints;

	devinfo->uas_sense_old = 0;

	for (i = 0; i < n_endpoints; i++) {
		unsigned char *extra = endpoint[i].extra;
		int len = endpoint[i].extralen;
		while (len > 1) {
			if (extra[1] == USB_DT_PIPE_USAGE) {
				unsigned pipe_id = extra[2];
				if (pipe_id > 0 && pipe_id < 5)
					eps[pipe_id - 1] = &endpoint[i];
				break;
			}
			len -= extra[0];
			extra += extra[0];
		}
	}

	/*
	 * Assume that if we didn't find a control pipe descriptor, we're
	 * using a device with old firmware that happens to be set up like
	 * this.
	 */
	if (!eps[0]) {
		devinfo->cmd_pipe = usb_sndbulkpipe(udev, 1);
		devinfo->status_pipe = usb_rcvbulkpipe(udev, 1);
		devinfo->data_in_pipe = usb_rcvbulkpipe(udev, 2);
		devinfo->data_out_pipe = usb_sndbulkpipe(udev, 2);

		eps[1] = usb_pipe_endpoint(udev, devinfo->status_pipe);
		eps[2] = usb_pipe_endpoint(udev, devinfo->data_in_pipe);
		eps[3] = usb_pipe_endpoint(udev, devinfo->data_out_pipe);
	} else {
		devinfo->cmd_pipe = usb_sndbulkpipe(udev,
						eps[0]->desc.bEndpointAddress);
		devinfo->status_pipe = usb_rcvbulkpipe(udev,
						eps[1]->desc.bEndpointAddress);
		devinfo->data_in_pipe = usb_rcvbulkpipe(udev,
						eps[2]->desc.bEndpointAddress);
		devinfo->data_out_pipe = usb_sndbulkpipe(udev,
						eps[3]->desc.bEndpointAddress);
	}

	devinfo->qdepth = usb_alloc_streams(devinfo->intf, eps + 1, 3, 256,
								GFP_KERNEL);
	if (devinfo->qdepth < 0) {
		devinfo->qdepth = 256;
		devinfo->use_streams = 0;
	} else {
		devinfo->use_streams = 1;
	}
}

/*
 * XXX: What I'd like to do here is register a SCSI host for each USB host in
 * the system.  Follow usb-storage's design of registering a SCSI host for
 * each USB device for the moment.  Can implement this by walking up the
 * USB hierarchy until we find a USB host.
 */
static int uas_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	int result, i;
	struct Scsi_Host *shost;
	struct uas_dev_info *devinfo;
	struct usb_device *udev = interface_to_usbdev(intf);

	if (uas_switch_interface(udev, intf))
		return -ENODEV;

	devinfo = kmalloc(sizeof(struct uas_dev_info), GFP_KERNEL);
	if (!devinfo)
		return -ENOMEM;

	atomic_set(&devinfo->resetting, 0);
	result = -ENOMEM;
	shost = scsi_host_alloc(&uas_host_template, sizeof(void *));
	if (!shost)
		goto free;

	shost->max_cmd_len = 16 + 252;
	shost->max_id = 1;
	shost->sg_tablesize = udev->bus->sg_tablesize;

	devinfo->intf = intf;
	devinfo->udev = udev;
	uas_configure_endpoints(devinfo);
	devinfo->anchors = kmalloc(sizeof(*devinfo->anchors)*devinfo->qdepth,
			GFP_KERNEL);
	if (!devinfo->anchors)
		goto free;
	for (i = 0; i < devinfo->qdepth; i++)
		init_usb_anchor(&devinfo->anchors[i]);

	devinfo->srcu = kmalloc(sizeof(*devinfo->srcu), GFP_KERNEL);
	if (!devinfo->srcu)
		goto free_anchors;
	init_srcu_struct(devinfo->srcu);

	result = scsi_add_host(shost, &intf->dev);
	if (result)
		goto free_srcu;
	shost->hostdata[0] = (unsigned long)devinfo;

	scsi_scan_host(shost);
	usb_set_intfdata(intf, shost);
	return result;

free_srcu:
	cleanup_srcu_struct(devinfo->srcu);
	kfree(devinfo->srcu);
free_anchors:
	kfree(devinfo->anchors);
free:
	kfree(devinfo);
	if (shost)
		scsi_host_put(shost);
	return result;
}

static int uas_pre_reset(struct usb_interface *intf)
{
	int i;
	struct usb_device *udev;
	struct Scsi_Host *shost;
	struct uas_dev_info *devinfo;
	struct uas_cmd_info *cmdinfo;
	struct uas_cmd_info *temp;
	struct usb_host_endpoint *eps[3];

/* XXX: Need to return 1 if it's not our device in error handling */
	udev = interface_to_usbdev(intf);
	shost = (struct Scsi_Host *) usb_get_intfdata(intf);
	devinfo = (struct uas_dev_info *) shost->hostdata[0];

	/* Synchronize with the readers of the resetting flag.
	 *
	 * Any currently running readers may submit URBs or schedule the
	 * workqueue, but any future readers will see the flag and return
	 * immediately.  Thus, when synchronize_srcu() finishes, we can stop the
	 * workqueue safely, and flush any pending commands.
	 *
	 * synchronize_srcu() will run an implicit memory barrier on all CPUs,
	 * so we're guaranteed future readers will see the flag when they grab
	 * the srcu_read_lock().  We only need to make sure the compiler doesn't
	 * optimize away the flag setting away by using atomic_t (which will do
	 * the same volatile trick as ACCESS_ONCE()).
	 */
	atomic_set(&devinfo->resetting, 1);
	synchronize_srcu(devinfo->srcu);

	/* Stop the workqueue, and stop it from rescheduling itself. */
	cancel_work_sync(&uas_work);
	/* Remove any partially queued commands from the work queue */
	list_for_each_entry_safe(cmdinfo, temp, &uas_work_list, list) {
		struct scsi_pointer *scp = (void *)cmdinfo;
		struct scsi_cmnd *cmnd = container_of(scp,
							struct scsi_cmnd, SCp);
		if (blk_rq_tagged(cmnd->request))
			uas_kill_tagged_urbs(
					&devinfo->anchors[cmnd->request->tag],
					cmdinfo);
		else
			uas_kill_tagged_urbs(
					&devinfo->anchors[0],
					cmdinfo);
		list_del_init(&cmdinfo->list);
	}

	/* Kill any commands that were fully queued. */
	for (i = 0; i < devinfo->qdepth; i++)
		usb_kill_anchored_urbs(&devinfo->anchors[i]);

	/* Free streams. */
	eps[0] = usb_pipe_endpoint(udev, devinfo->status_pipe);
	eps[1] = usb_pipe_endpoint(udev, devinfo->data_in_pipe);
	eps[2] = usb_pipe_endpoint(udev, devinfo->data_out_pipe);
	usb_free_streams(intf, eps, 3, GFP_KERNEL);

	return 0;
}

static int uas_post_reset(struct usb_interface *intf)
{
	struct Scsi_Host *shost;
	struct uas_dev_info *devinfo;
	int qdepth;

	shost = (struct Scsi_Host *) usb_get_intfdata(intf);
	devinfo = (struct uas_dev_info *) shost->hostdata[0];
/* XXX: Need to return 1 if it's not our device in error handling */
	/* Set the correct alt setting and re-allocate streams.
	 * The USB core will disconnect and re-probe if the descriptors
	 * (including the SS endpoint companion descriptors) change.
	 * So qdepth should be the same, unless the xHCI driver failed to
	 * allocate streams.  Disconnect and re-probe in that case.
	 */
	qdepth = devinfo->qdepth;
	uas_configure_endpoints(devinfo);
	if (qdepth != devinfo->qdepth)
		return -ENODEV;

	/* Make sure that the CPU doesn't reorder writes such that clearing the
	 * reset flag happens before setting up the streams
	 */
	smp_wmb();
	atomic_set(&devinfo->resetting, 0);
	/* Make sure that all future readers will see the cleared flag before
	 * returning from post-reset.  Otherwise the SCSI core could schedule a
	 * command queue on a separate CPU where the flag might be stale.
	 */
	synchronize_srcu(devinfo->srcu);
	return 0;
}

static void uas_disconnect(struct usb_interface *intf)
{
	struct Scsi_Host *shost = usb_get_intfdata(intf);
	struct uas_dev_info *devinfo = (void *)shost->hostdata[0];

	/* Clean up any pending commands and free streams */
	uas_pre_reset(intf);
	scsi_remove_host(shost);

	cleanup_srcu_struct(devinfo->srcu);
	kfree(devinfo->srcu);
	kfree(devinfo->anchors);
	kfree(devinfo);
}

/*
 * XXX: Should this plug into libusual so we can auto-upgrade devices from
 * Bulk-Only to UAS?
 */
static struct usb_driver uas_driver = {
	.name = "uas",
	.probe = uas_probe,
	.disconnect = uas_disconnect,
	.pre_reset = uas_pre_reset,
	.post_reset = uas_post_reset,
	.id_table = uas_usb_ids,
	/* UAS needs to free URBs and streams before USB core disables eps */
	.soft_unbind = 1,
};

static int uas_init(void)
{
	return usb_register(&uas_driver);
}

static void uas_exit(void)
{
	usb_deregister(&uas_driver);
}

module_init(uas_init);
module_exit(uas_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matthew Wilcox and Sarah Sharp");
