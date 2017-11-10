#ifndef CUSTOMDEVICE_H
#define CUSTOMDEVICE_H

#include <QtCore/QIODevice>

class CustomDevice : public QIODevice
{
	Q_OBJECT

public:
	enum class Feature : unsigned char
	{
		Encryption = 1,
		NakedEncryption = 2
	};

	explicit CustomDevice(QIODevice *device, QObject *parent = nullptr);

	/**
	 * @param device Underlying device, where processed data is wrote or from which comes data to be read and processed.
	 * @param features When write to CustomDevice, data is first processed by first feature in the list.
	 * When read from CustomDevice, data is first processed by last feature in the list.
	 * It means that same list should be passed when both writing and reading.
	 */
	explicit CustomDevice(QIODevice *device, const QList<Feature> &features, QObject *parent = nullptr);

	void close() override;
	bool isSequential() const override;
	bool open(OpenMode mode) override;

	QIODevice* getChainDevice(int index);

protected:
	qint64 readData(char *data, qint64 length) override;
	qint64 writeData(const char *data, qint64 length) override;

private:
	QIODevice *m_targetDevice;
	QList<QIODevice*> m_chainDevices;
};

#endif
