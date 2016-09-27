#include "EncryptedFile.h"

EncryptedFile::EncryptedFile(QObject *parent) : QIODevice(parent),
	m_file(nullptr),
	m_writingBuffered(0),
	m_hasKey(false),
	m_initialized(false),
	m_writingInitialized(false),
	m_readingInitialized(true)
{
	register_cipher(&aes_desc);

	if (register_hash(&sha256_desc) == -1)
	{
		return;
	}

	if (register_prng(&yarrow_desc) == -1)
	{
		return;
	}

	if (register_prng(&sprng_desc) == -1)
	{
		return;
	}

	m_cipherIndex = find_cipher("aes");
	if (m_cipherIndex == -1)
	{
		return;
	}

	m_hashIndex = find_hash("sha256");
	if (m_hashIndex == -1)
	{
		return;
	}

	m_initialVectorSize = cipher_descriptor[m_cipherIndex].block_length;
	m_keySize = hash_descriptor[m_hashIndex].hashsize;
	if (cipher_descriptor[m_cipherIndex].keysize(&m_keySize) != CRYPT_OK)
	{
		return;
	}

	m_initialized = true;
}

EncryptedFile::EncryptedFile(const QString &name, QObject *parent) : EncryptedFile(parent)
{
	m_file = new QFile(name, this);
}

void EncryptedFile::close()
{
	writeBuffer();

	m_file->close();

	setOpenMode(m_file->openMode());
}

bool EncryptedFile::isSequential() const
{
	return true;
}

bool EncryptedFile::open(QIODevice::OpenMode mode)
{
	if (isOpen())
	{
		return true;
	}

	if (!m_initialized || !m_hasKey)
	{
		return false;
	}

	if ((mode & QIODevice::ReadWrite) == QIODevice::ReadWrite || (mode & QIODevice::Append))
	{
		return false;
	}

	if (!m_file->open(mode))
	{
		return false;
	}

	setOpenMode(m_file->openMode());

	if (mode & QIODevice::ReadOnly)
	{
		initReading();

		if (!m_readingInitialized)
		{
			m_file->close();
			setOpenMode(m_file->openMode());

			return false;
		}
	}
	else if (mode & QIODevice::WriteOnly)
	{
		initWriting();

		if (!m_writingInitialized)
		{
			m_file->close();
			setOpenMode(m_file->openMode());

			return false;
		}
	}
}

void EncryptedFile::setKey(const QByteArray &plainKey)
{
	unsigned long outlen = sizeof(m_key);
	m_hasKey = false;

	if ((errno = hash_memory(m_hashIndex, reinterpret_cast<const unsigned char*>(plainKey.constData()), plainKey.size(), m_key, &outlen)) != CRYPT_OK)
	{
		return;
	}

	m_hasKey = true;
}

void EncryptedFile::setFile(QFile *file)
{
	m_file = file;
}

qint64 EncryptedFile::readData(char *data, qint64 len)
{

}

qint64 EncryptedFile::readLineData(char *data, qint64 maxlen)
{

}

qint64 EncryptedFile::writeData(const char *data, qint64 len)
{
	if (!m_writingInitialized)
	{
		initWriting();
	}

	if (!m_writingInitialized)
	{
		return -1;
	}

	qint64 pos = 0;

	while (pos != len)
	{
		int bytesToCopy = qMin(qint64(sizeof (m_writingBuffer) - m_writingBuffered), (len - pos));

		memcpy(&m_writingBuffer[m_writingBuffered], &data[pos], bytesToCopy);

		m_writingBuffered += bytesToCopy;
		pos += bytesToCopy;

		if (m_writingBuffered != sizeof (m_writingBuffer))
		{
			break;
		}

		if (!writeBuffer())
		{
			return -1;
		}
	}

	return len;
}

bool EncryptedFile::writeBuffer()
{
	unsigned char ciphertext[sizeof (m_writingBuffer)];

	if ((errno = ctr_encrypt(m_writingBuffer, ciphertext, m_writingBuffered, &m_ctr)) != CRYPT_OK)
	{
		return false;
	}

	if (m_file->write(reinterpret_cast<const char*>(ciphertext), m_writingBuffered) == -1)
	{
		return false;
	}

	m_writingBuffered = 0;

	return true;
}

void EncryptedFile::initWriting()
{
	prng_state prng;
	unsigned char initialVector[MAXBLOCKSIZE];

	rng_make_prng(128, find_prng("yarrow"), &prng, NULL);

	int randomBytesRead = yarrow_read(initialVector, m_initialVectorSize, &prng);

	if (randomBytesRead != m_initialVectorSize)
	{
		return;
	}

	if ((errno = ctr_start(m_cipherIndex, initialVector, m_key, m_keySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &m_ctr)) != CRYPT_OK)
	{
		return;
	}

	m_writingInitialized = true;

	if (m_file->write(reinterpret_cast<const char*>(initialVector), m_initialVectorSize) != m_initialVectorSize)
	{
		m_writingInitialized = false;

		return;
	}
}

void EncryptedFile::initReading()
{
	;
}
