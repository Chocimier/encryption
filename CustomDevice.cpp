#include "CustomDevice.h"

#include "EncryptionDevice.h"

CustomDevice::CustomDevice(QIODevice *device, QObject *parent) : CustomDevice(device, QList<CustomDevice::Feature>(), parent)
{
}

CustomDevice::CustomDevice(QIODevice *device, const QList<CustomDevice::Feature> &features, QObject *parent) : QIODevice(parent),
    m_targetDevice(NULL)
{
	m_chainDevices.reserve(features.size());

	for (int i = features.size() - 1; i >= 0; --i)
	{
		if (features.at(i) == Feature::Encryption)
		{
			device = new EncryptionDevice(device, this);
		}

		m_chainDevices.prepend(device);
	}

	m_targetDevice = device;
}

void CustomDevice::close()
{
	if (m_targetDevice)
	{
		m_targetDevice->close();
	}
}

bool CustomDevice::isSequential() const
{
	if (m_targetDevice)
	{
		return m_targetDevice->isSequential();
	}

	return false;
}

bool CustomDevice::open(QIODevice::OpenMode mode)
{
	if (m_targetDevice)
	{
		bool result(m_targetDevice->open(mode));

		setOpenMode(m_targetDevice->openMode());

		return result;
	}

	return false;
}

QIODevice* CustomDevice::getChainDevice(int index)
{
	if (index < 0 || m_chainDevices.size() <= index)
	{
		return NULL;
	}

	return m_chainDevices.at(index);
}

qint64 CustomDevice::readData(char *data, qint64 length)
{
	if (m_targetDevice)
	{
		return m_targetDevice->read(data, length);
	}

	return -1;
}

qint64 CustomDevice::writeData(const char *data, qint64 length)
{
	if (m_targetDevice)
	{
		return m_targetDevice->write(data, length);
	}

	return -1;
}
