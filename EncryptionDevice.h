#ifndef ENCRYPTIONDEVICE_H
#define ENCRYPTIONDEVICE_H

#include <QtCore/QIODevice>

#include <tomcrypt.h>

class EncryptionDevice : public QIODevice
{
	Q_OBJECT

public:
	explicit EncryptionDevice(QIODevice *targetDevice, QObject *parent = nullptr);

	void close() override;
	void setKey(const QByteArray &plainKey);
	bool isSequential() const override;
	bool open(OpenMode mode) override;

public slots:
	void setHeaderEnabled(bool headerEnabled);

protected:
	qint64 readData(char *data, qint64 length) override;
	qint64 writeData(const char *data, qint64 length) override;
	bool writeBufferEncrypted();
	bool applyPkcs(const unsigned char *salt);

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
	bool m_headerEnabled;
	bool m_hasPlainKey;
	bool m_isValid;
	bool m_readAll;

	static const char *m_header;
	static int m_headerSize;
	static int m_pkcsIterationCount;
	static int m_pkcsSaltSize;
	static int m_pkcsResultSize;
	static int m_ctrMode;
};

#endif
