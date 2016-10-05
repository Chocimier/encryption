#ifndef CUSTOMDEVICE_H
#define CUSTOMDEVICE_H

#include <QtCore/QIODevice>

class CustomDevice : public QIODevice
{
	Q_OBJECT

public:
	enum class Feature : unsigned char
	{
		Encryption
	};

	explicit CustomDevice(QIODevice *device, QObject *parent = 0);
	explicit CustomDevice(QIODevice *device, const QList<Feature> &features, QObject *parent = 0);

	void close();
	bool isSequential() const;
	bool open(OpenMode mode);

	QIODevice* getChainDevice(int index);

protected:
	qint64 readData(char *data, qint64 length);
	qint64 writeData(const char *data, qint64 length);

private:
	QIODevice *m_targetDevice;
	QList<QIODevice*> m_chainDevices;
};

#endif
