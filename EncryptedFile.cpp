#include "EncryptedFile.h"

char EncryptedFile::m_header[] = {'E', 'F', '1'};

EncryptedFile::EncryptedFile(QIODevice *targetDevice, QObject *parent) : QIODevice(parent),
	m_device(nullptr),
	m_readingBuffered(0),
	m_writingBuffered(0),
	m_hasKey(false),
	m_initialized(false),
	m_writingInitialized(false),
	m_readingInitialized(false)
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

	m_initializationVectorSize = cipher_descriptor[m_cipherIndex].block_length;
	m_keySize = hash_descriptor[m_hashIndex].hashsize;
	if (cipher_descriptor[m_cipherIndex].keysize(&m_keySize) != CRYPT_OK)
	{
		return;
	}

	m_initialized = true;

	m_device = targetDevice;
}

void EncryptedFile::close()
{
	if (openMode().testFlag(QIODevice::WriteOnly))
	{
		writeBuffer();

		m_device->close();

		setOpenMode(m_device->openMode());
	}
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

	if (mode.testFlag(QIODevice::ReadWrite) || mode.testFlag(QIODevice::Append))
	{
		return false;
	}

	if (!m_device->open(mode))
	{
		return false;
	}

	setOpenMode(m_device->openMode());

	if (mode.testFlag(QIODevice::ReadOnly))
	{
		initReading();

		if (!m_readingInitialized)
		{
			m_device->close();
			setOpenMode(m_device->openMode());

			return false;
		}
	}
	else if (mode.testFlag(QIODevice::WriteOnly))
	{
		initWriting();

		if (!m_writingInitialized)
		{
			m_device->close();
			setOpenMode(m_device->openMode());

			return false;
		}
	}

	return true;
}

void EncryptedFile::setKey(const QByteArray &plainKey)
{
	unsigned long outlen = sizeof(m_key);
	m_hasKey = false;

	if (hash_memory(m_hashIndex, reinterpret_cast<const unsigned char*>(plainKey.constData()), plainKey.size(), m_key, &outlen) != CRYPT_OK)
	{
		return;
	}

	m_hasKey = true;
}

qint64 EncryptedFile::readData(char *data, qint64 len)
{
	unsigned char ciphertext[sizeof (m_readingBuffer)];
	qint64 pos = 0;

	if (m_readingBuffered)
	{
		qint64 bytesToCopy = qMin(qint64(m_readingBuffered), len);

		memcpy(data, &m_readingBuffer[(sizeof (m_readingBuffer)) - m_readingBuffered], bytesToCopy);

		pos += bytesToCopy;
		m_readingBuffered -= bytesToCopy;
	}

	while (pos < len)
	{
		qint64 bytesRead = m_device->read(reinterpret_cast<char*>(ciphertext), sizeof (ciphertext));

		if (bytesRead == -1)
		{
			return -1;
		}

		if (ctr_decrypt(ciphertext,m_readingBuffer,bytesRead,&m_ctr) != CRYPT_OK)
		{
			return -1;
		}

		qint64 bytesToCopy = qMin(bytesRead, (len - pos));

		if (bytesToCopy < bytesRead)
		{
			m_readingBuffered = bytesRead - bytesToCopy;
		}

		memcpy(&data[pos], m_readingBuffer, bytesToCopy);

		pos += bytesToCopy;

		if (bytesRead < sizeof (ciphertext))
		{
			break;
		}
	}

	return pos;
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

	if (ctr_encrypt(m_writingBuffer, ciphertext, m_writingBuffered, &m_ctr) != CRYPT_OK)
	{
		return false;
	}

	if (m_device->write(reinterpret_cast<const char*>(ciphertext), m_writingBuffered) == -1)
	{
		return false;
	}

	m_writingBuffered = 0;

	return true;
}

void EncryptedFile::initWriting()
{
	prng_state prng;
	unsigned char initializationVector[MAXBLOCKSIZE];

	rng_make_prng(128, find_prng("yarrow"), &prng, NULL);

	int randomBytesRead = yarrow_read(initializationVector, m_initializationVectorSize, &prng);

	if (randomBytesRead != m_initializationVectorSize)
	{
		return;
	}

	if (ctr_start(m_cipherIndex, initializationVector, m_key, m_keySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &m_ctr) != CRYPT_OK)
	{
		return;
	}

	m_writingInitialized = true;

	if (m_device->write(m_header, sizeof (m_header)) != sizeof (m_header))
	{
		m_writingInitialized = false;

		return;
	}

	if (m_device->write(reinterpret_cast<const char*>(initializationVector), m_initializationVectorSize) != m_initializationVectorSize)
	{
		m_writingInitialized = false;

		return;
	}
}

void EncryptedFile::initReading()
{
	unsigned char initializationVector[MAXBLOCKSIZE];

	m_readingInitialized = true;

	char header[sizeof (m_header)];

	if (m_device->read(header, sizeof (m_header)) != sizeof (m_header) || memcmp(m_header, header, sizeof (m_header)))
	{
		m_readingInitialized = false;

		return;
	}

	if (m_device->read(reinterpret_cast<char*>(initializationVector), m_initializationVectorSize) != m_initializationVectorSize)
	{
		m_readingInitialized = false;

		return;
	}

	if (ctr_start(m_cipherIndex, initializationVector, m_key, m_keySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &m_ctr) != CRYPT_OK)
	{
		m_readingInitialized = false;

		return;
	}
}
