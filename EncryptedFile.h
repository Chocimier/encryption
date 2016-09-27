#ifndef ENCRYPTEDFILE_H
#define ENCRYPTEDFILE_H

#include <QtCore/QFile>
#include <QtCore/QIODevice>

#include <tomcrypt.h>

class EncryptedFile : public QIODevice
{
	Q_OBJECT

public:
	explicit EncryptedFile(QObject *parent = 0);
	explicit EncryptedFile(const QString &name, QObject *parent = 0);

	void close();
	bool isSequential() const;
	bool open(OpenMode mode);

	void setKey(const QByteArray &plainKey);
	void setFile(QFile *file);

protected:
	qint64 readData(char *data, qint64 len);
	qint64 readLineData(char *data, qint64 maxlen);
	qint64 writeData(const char *data, qint64 len);
	bool writeBuffer();
	void initWriting();
	void initReading();

private:
	QFile *m_file;
	symmetric_CTR m_ctr;
	unsigned char m_key[MAXBLOCKSIZE];
	unsigned char m_writingBuffer[512];
	int m_cipherIndex;
	int m_hashIndex;
	int m_writingBuffered;
	int m_keySize;
	int m_initialVectorSize;
	bool m_hasKey;
	bool m_initialized;
	bool m_writingInitialized;
	bool m_readingInitialized;
};

#endif
