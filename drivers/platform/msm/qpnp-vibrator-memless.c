/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/of_device.h>
#include <linux/spmi.h>
#include <linux/input.h>

#include <linux/qpnp/vibrator.h>

#define QPNP_VIB_VTG_CTL(base)		(base + 0x41)
#define QPNP_VIB_EN_CTL(base)		(base + 0x46)

#define QPNP_VIB_DEFAULT_TIMEOUT	15000
#define QPNP_VIB_DEFAULT_VTG_LVL	3100
#define QPNP_VIB_DEFAULT_VTG_MAX	3100
#define QPNP_VIB_DEFAULT_VTG_MIN	1200

#define QPNP_VIB_QT5_LEVEL_MIN		0
#define QPNP_VIB_QT5_LEVEL_MAX		127

#define QPNP_VIB_EN			BIT(7)
#define QPNP_VIB_VTG_SET_MASK		0x1F
#define QPNP_VIB_LOGIC_SHIFT		4

struct qpnp_vib {
	struct spmi_device *spmi;
	struct work_struct work;
	struct input_dev *input_device;

	u8  reg_vtg_ctl;
	u8  reg_en_ctl;
	u16 base;
	int state;
	int vtg_min;
	int vtg_max;
	int vtg_level;
	int timeout;
	spinlock_t lock;
};

static struct qpnp_vib *vib_dev;

static int qpnp_vib_read_u8(struct qpnp_vib *vib, u8 *data, u16 reg)
{
	int rc;

	rc = spmi_ext_register_readl(vib->spmi->ctrl, vib->spmi->sid,
							reg, data, 1);
	if (rc < 0)
		dev_err(&vib->spmi->dev,
			"Error reading address: %X - ret %X\n", reg, rc);

	return rc;
}

static int qpnp_vib_write_u8(struct qpnp_vib *vib, u8 *data, u16 reg)
{
	int rc;

	rc = spmi_ext_register_writel(vib->spmi->ctrl, vib->spmi->sid,
							reg, data, 1);
	if (rc < 0)
		dev_err(&vib->spmi->dev,
			"Error writing address: %X - ret %X\n", reg, rc);

	return rc;
}

int qpnp_vibrator_config(struct qpnp_vib_config *vib_cfg)
{
	u8 reg = 0;
	int rc = -EINVAL, level;

	if (vib_dev == NULL) {
		pr_err("%s: vib_dev is NULL\n", __func__);
		return -ENODEV;
	}

	level = vib_cfg->drive_mV / 100;
	if (level) {
		if ((level < vib_dev->vtg_min) ||
				(level > vib_dev->vtg_max)) {
			dev_err(&vib_dev->spmi->dev, "Invalid voltage level\n");
			return -EINVAL;
		}
	} else {
		dev_err(&vib_dev->spmi->dev, "Voltage level not specified\n");
		return -EINVAL;
	}

	/* Configure the VTG CTL regiser */
	reg = vib_dev->reg_vtg_ctl;
	reg &= ~QPNP_VIB_VTG_SET_MASK;
	reg |= (level & QPNP_VIB_VTG_SET_MASK);
	rc = qpnp_vib_write_u8(vib_dev, &reg, QPNP_VIB_VTG_CTL(vib_dev->base));
	if (rc)
		return rc;
	vib_dev->reg_vtg_ctl = reg;

	/* Configure the VIB ENABLE regiser */
	reg = vib_dev->reg_en_ctl;
	reg |= (!!vib_cfg->active_low) << QPNP_VIB_LOGIC_SHIFT;
	if (vib_cfg->enable_mode == QPNP_VIB_MANUAL)
		reg |= QPNP_VIB_EN;
	else
		reg |= BIT(vib_cfg->enable_mode - 1);
	rc = qpnp_vib_write_u8(vib_dev, &reg, QPNP_VIB_EN_CTL(vib_dev->base));
	if (rc < 0)
		return rc;
	vib_dev->reg_en_ctl = reg;

	return rc;
}
EXPORT_SYMBOL(qpnp_vibrator_config);

static int qpnp_vib_set(struct qpnp_vib *vib, int new_level)
{
	int rc;
	u8 val;

	vib->vtg_level = (((vib->vtg_max - vib->vtg_min)*(new_level - QPNP_VIB_QT5_LEVEL_MIN))
				/(QPNP_VIB_QT5_LEVEL_MAX - QPNP_VIB_QT5_LEVEL_MIN))
				+ vib->vtg_min;

	if (vib->vtg_level < vib->vtg_min)
		vib->vtg_level = vib->vtg_min;
	if (vib->vtg_level > vib->vtg_max)
		vib->vtg_level = vib->vtg_max;

	pr_devel("setting vibration to %d, scaled to %d\n", new_level, vib->vtg_level);

	if (new_level) {
		val = vib->reg_vtg_ctl;
		val &= ~QPNP_VIB_VTG_SET_MASK;
		val |= (vib->vtg_level & QPNP_VIB_VTG_SET_MASK);
		rc = qpnp_vib_write_u8(vib, &val, QPNP_VIB_VTG_CTL(vib->base));
		if (rc < 0)
			return rc;
		vib->reg_vtg_ctl = val;
		val = vib->reg_en_ctl;
		val |= QPNP_VIB_EN;
		rc = qpnp_vib_write_u8(vib, &val, QPNP_VIB_EN_CTL(vib->base));
		if (rc < 0)
			return rc;
		vib->reg_en_ctl = val;
	} else {
		val = vib->reg_en_ctl;
		val &= ~QPNP_VIB_EN;
		rc = qpnp_vib_write_u8(vib, &val, QPNP_VIB_EN_CTL(vib->base));
		if (rc < 0)
			return rc;
		vib->reg_en_ctl = val;
	}

	return rc;
}

static void qpnp_vib_update(struct work_struct *work)
{
	struct qpnp_vib *vib = container_of(work, struct qpnp_vib,
					 work);
	pr_devel("updating to %d\n", vib->state);
	qpnp_vib_set(vib, vib->state);
}

#ifdef CONFIG_PM
static int qpnp_vibrator_suspend(struct device *dev)
{
	struct qpnp_vib *vib = dev_get_drvdata(dev);

	cancel_work_sync(&vib->work);
	/* turn-off vibrator */
	qpnp_vib_set(vib, 0);

	return 0;
}
#endif

static int qpnp_vibrator_play_effect(struct input_dev *dev, void *data,
				struct ff_effect *effect)
{
	struct qpnp_vib *vib = input_get_drvdata(dev);

	pr_devel("ff rumble strong %d, weak %d\n",  effect->u.rumble.strong_magnitude, effect->u.rumble.weak_magnitude);

	/* support basic vibration */
	vib->state = effect->u.rumble.strong_magnitude >> 8;
	if (!vib->state)
		vib->state = effect->u.rumble.weak_magnitude >> 9;

	schedule_work(&vib->work);

	return 0;
}

static void qpnp_vibrator_close(struct input_dev *dev)
{
	struct qpnp_vib *vib = input_get_drvdata(dev);

	cancel_work_sync(&vib->work);
	/* turn-off vibrator */
	qpnp_vib_set(vib, 0);
}

static SIMPLE_DEV_PM_OPS(qpnp_vibrator_pm_ops, qpnp_vibrator_suspend, NULL);

static int __devinit qpnp_vibrator_probe(struct spmi_device *spmi)
{
	struct qpnp_vib *vib;
	struct resource *vib_resource;
	int rc, ret;
	u8 val;
	u32 temp_val;

	vib = devm_kzalloc(&spmi->dev, sizeof(*vib), GFP_KERNEL);
	if (!vib)
		return -ENOMEM;

	vib->spmi = spmi;

	vib->timeout = QPNP_VIB_DEFAULT_TIMEOUT;
	rc = of_property_read_u32(spmi->dev.of_node,
			"qcom,vib-timeout-ms", &temp_val);
	if (!rc) {
		vib->timeout = temp_val;
	} else if (rc != EINVAL) {
		dev_err(&spmi->dev, "Unable to read vib timeout\n");
		return rc;
	}

	vib->vtg_level = QPNP_VIB_DEFAULT_VTG_LVL;
	rc = of_property_read_u32(spmi->dev.of_node,
			"qcom,vib-vtg-level-mV", &temp_val);
	if (!rc) {
		vib->vtg_level = temp_val;
	} else if (rc != -EINVAL) {
		dev_err(&spmi->dev, "Unable to read vtg level\n");
		return rc;
	}

	vib->vtg_max = QPNP_VIB_DEFAULT_VTG_MAX;
	rc = of_property_read_u32(spmi->dev.of_node,
			"qcom,vib-vtg-max-mV", &temp_val);
	if (!rc) {
		vib->vtg_max = min(temp_val, (u32)QPNP_VIB_DEFAULT_VTG_MAX);
	} else if (rc != -EINVAL) {
		dev_err(&spmi->dev, "Unable to read vtg max level\n");
		return rc;
	}

	vib->vtg_min = QPNP_VIB_DEFAULT_VTG_MIN;
	rc = of_property_read_u32(spmi->dev.of_node,
			"qcom,vib-vtg-min-mV", &temp_val);
	if (!rc) {
		vib->vtg_min = max(temp_val, (u32)QPNP_VIB_DEFAULT_VTG_MIN);
	} else if (rc != -EINVAL) {
		dev_err(&spmi->dev, "Unable to read vtg min level\n");
		return rc;
	}

	vib->vtg_level /= 100;
	vib->vtg_min /= 100;
	vib->vtg_max /= 100;

	vib_resource = spmi_get_resource(spmi, 0, IORESOURCE_MEM, 0);
	if (!vib_resource) {
		dev_err(&spmi->dev, "Unable to get vibrator base address\n");
		return -EINVAL;
	}
	vib->base = vib_resource->start;

	/* save the control registers values */
	rc = qpnp_vib_read_u8(vib, &val, QPNP_VIB_VTG_CTL(vib->base));
	if (rc < 0)
		return rc;
	vib->reg_vtg_ctl = val;

	rc = qpnp_vib_read_u8(vib, &val, QPNP_VIB_EN_CTL(vib->base));
	if (rc < 0)
		return rc;
	vib->reg_en_ctl = val;

	spin_lock_init(&vib->lock);
	INIT_WORK(&vib->work, qpnp_vib_update);

	dev_set_drvdata(&spmi->dev, vib);

	vib_dev = vib;

	vib->input_device = input_allocate_device();
	if (!vib->input_device) {
		pr_err("failed to allocate input device\n");
		rc = -ENOMEM;
		goto err_mem_allocate;
	}

	input_set_drvdata(vib->input_device, vib);
	vib->input_device->name = "qpnp-vibrator-memless";
	vib->input_device->dev.parent = &spmi->dev;
	input_set_capability(vib->input_device, EV_FF, FF_RUMBLE);
	vib->input_device->close = qpnp_vibrator_close;

	ret = input_ff_create_memless(vib->input_device, NULL, qpnp_vibrator_play_effect);

	if (ret < 0) {
		pr_err("unable to register ff memless (%d)\n", ret);
		goto err_free_dev;
	}
	ret = input_register_device(vib->input_device);
	if (ret < 0) {
		pr_err("unable to register input device (%d)\n", ret);
		goto err_ff_destroy;
	}

	return rc;

err_ff_destroy:
	input_ff_destroy(vib->input_device);
err_free_dev:
	input_free_device(vib->input_device);
err_mem_allocate:
	kfree(vib);
	return rc;
}

static int  __devexit qpnp_vibrator_remove(struct spmi_device *spmi)
{
	struct qpnp_vib *vib = dev_get_drvdata(&spmi->dev);

	cancel_work_sync(&vib->work);
	input_unregister_device(vib->input_device);

	return 0;
}

static struct of_device_id spmi_match_table[] = {
	{	.compatible = "qcom,qpnp-vibrator",
	},
	{}
};

static struct spmi_driver qpnp_vibrator_driver = {
	.driver		= {
		.name	= "qcom,qpnp-vibrator",
		.of_match_table = spmi_match_table,
		.pm	= &qpnp_vibrator_pm_ops,
	},
	.probe		= qpnp_vibrator_probe,
	.remove		= __devexit_p(qpnp_vibrator_remove),
};

static int __init qpnp_vibrator_init(void)
{
	return spmi_driver_register(&qpnp_vibrator_driver);
}
module_init(qpnp_vibrator_init);

static void __exit qpnp_vibrator_exit(void)
{
	return spmi_driver_unregister(&qpnp_vibrator_driver);
}
module_exit(qpnp_vibrator_exit);

MODULE_DESCRIPTION("qpnp vibrator ff-memless driver");
MODULE_LICENSE("GPL v2");
