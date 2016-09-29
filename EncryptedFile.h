#ifndef ENCRYPTEDFILE_H
#define ENCRYPTEDFILE_H

#include <QtCore/QIODevice>

#include <tomcrypt.h>

class EncryptedFile : public QIODevice
{
	Q_OBJECT

public:
	explicit EncryptedFile(QIODevice *targetDevice, QObject *parent = 0);

	void close();
	bool isSequential() const;
	bool open(OpenMode mode);

	void setKey(const QByteArray &plainKey);

protected:
	qint64 readData(char *data, qint64 len);
	qint64 writeData(const char *data, qint64 len);
	bool writeBuffer();
	void initWriting();
	void initReading();

private:
	QIODevice *m_device;
	symmetric_CTR m_ctr;
	unsigned char m_key[MAXBLOCKSIZE];
	unsigned char m_readingBuffer[MAXBLOCKSIZE];
	unsigned char m_writingBuffer[MAXBLOCKSIZE];
	int m_cipherIndex;
	int m_hashIndex;
	int m_readingBuffered;
	int m_writingBuffered;
	int m_keySize;
	int m_blockSize;
	int m_initializationVectorSize;
	bool m_hasKey;
	bool m_initialized;
	bool m_writingInitialized;
	bool m_readingInitialized;

	static char m_header[];
};

#endif
