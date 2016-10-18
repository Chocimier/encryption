#ifndef ENCRYPTIONDEVICE_H
#define ENCRYPTIONDEVICE_H

#include <QtCore/QIODevice>

#include <tomcrypt.h>

class EncryptionDevice : public QIODevice
{
	Q_OBJECT

public:
	explicit EncryptionDevice(QIODevice *targetDevice, QObject *parent = 0);

	void close();
	bool isSequential() const;
	bool open(OpenMode mode);
	void setKey(const QByteArray &plainKey);

protected:
	qint64 readData(char *data, qint64 length);
	qint64 writeData(const char *data, qint64 length);
	bool writeBufferEncrypted();
	void initReading();
	void initWriting();
	bool applyPKCS(const unsigned char *salt);

private:
	QIODevice *m_device;
	QByteArray m_plainKey;
	symmetric_CTR m_ctr;
	unsigned char m_key[MAXBLOCKSIZE];
	unsigned char m_initializationVector[MAXBLOCKSIZE];
	unsigned char m_readingBuffer[MAXBLOCKSIZE];
	unsigned char m_writingBuffer[MAXBLOCKSIZE];
	qint64 m_readingBuffered;
	int m_blockSize;
	int m_cipherIndex;
	int m_hashIndex;
	int m_initializationVectorSize;
	int m_keySize;
	int m_writingBuffered;
	bool m_hasPlainKey;
	bool m_isValid;
	bool m_readAll;

	static char m_header[];
	static int m_PKCSIterationCount;
	static int m_PKCSSaltSize;
	static int m_PKCSResultSize;
	static int m_ctrMode;
};

#endif
