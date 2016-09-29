#include "EncryptedFile.h"

char EncryptedFile::m_header[]{'E', 'F', '1'};

EncryptedFile::EncryptedFile(QIODevice *targetDevice, QObject *parent) : QIODevice(parent),
	m_device(targetDevice),
	m_readingBuffered(0),
	m_writingBuffered(0),
	m_hasKey(false),
	m_isValid(false),
	m_readAll(false)
{
	register_cipher(&aes_desc);
	register_hash(&sha256_desc);

	m_cipherIndex = find_cipher("aes");
	m_hashIndex = find_hash("sha256");

	if (m_cipherIndex == -1  || m_hashIndex == -1 || register_prng(&yarrow_desc) == -1 || register_prng(&sprng_desc) == -1)
	{
		return;
	}

	m_keySize = hash_descriptor[m_hashIndex].hashsize;
	m_blockSize = cipher_descriptor[m_cipherIndex].block_length;
	m_initializationVectorSize = cipher_descriptor[m_cipherIndex].block_length;

	if (cipher_descriptor[m_cipherIndex].keysize(&m_keySize) != CRYPT_OK)
	{
		return;
	}

	m_isValid = true;
}

void EncryptedFile::close()
{
	if (openMode().testFlag(QIODevice::WriteOnly))
	{
		writeBufferEncrypted();

		m_device->close();

		setOpenMode(m_device->openMode());
	}

	m_isValid = false;
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

	if (!m_isValid || !m_hasKey || mode.testFlag(QIODevice::ReadWrite) || mode.testFlag(QIODevice::Append) || !m_device->open(mode))
	{
		return false;
	}

	setOpenMode(m_device->openMode());

	if (mode.testFlag(QIODevice::ReadOnly))
	{
		initReading();
	}
	else if (mode.testFlag(QIODevice::WriteOnly))
	{
		initWriting();
	}

	if (!m_isValid)
	{
		m_device->close();

		setOpenMode(m_device->openMode());

		return false;
	}

	return true;
}

void EncryptedFile::setKey(const QByteArray &plainKey)
{
	unsigned long outlen(sizeof m_key);

	m_hasKey = (hash_memory(m_hashIndex, reinterpret_cast<const unsigned char*>(plainKey.constData()), plainKey.size(), m_key, &outlen) == CRYPT_OK);

}

qint64 EncryptedFile::readData(char *data, qint64 length)
{
	unsigned char ciphertext[MAXBLOCKSIZE] = {};
	qint64 position(0);

	if (!m_isValid || (m_readAll && m_readingBuffered == 0))
	{
		return -1;
	}

	if (m_readingBuffered)
	{
		const qint64 bytesToCopy(qMin(m_readingBuffered, length));

		memcpy(data, &m_readingBuffer[m_blockSize - m_readingBuffered], bytesToCopy);

		position += bytesToCopy;
		m_readingBuffered -= bytesToCopy;
	}

	while (position < length && !m_readAll)
	{
		const qint64 bytesRead(m_device->read(reinterpret_cast<char*>(ciphertext), m_blockSize));

		if (bytesRead == -1)
		{
			m_isValid = false;

			return -1;
		}

		if (ctr_decrypt(ciphertext, m_readingBuffer, bytesRead, &m_ctr) != CRYPT_OK)
		{
			m_isValid = false;

			return -1;
		}

		const qint64 bytesToCopy(qMin(bytesRead, (length - position)));

		if (bytesToCopy < bytesRead)
		{
			m_readingBuffered = bytesRead - bytesToCopy;
		}

		memcpy(&data[position], m_readingBuffer, bytesToCopy);

		position += bytesToCopy;

		if (bytesRead < m_blockSize)
		{
			m_readAll = true;
		}
	}

	return position;
}

qint64 EncryptedFile::writeData(const char *data, qint64 length)
{
	if (!m_isValid)
	{
		return -1;
	}

	qint64 position(0);

	while (position < length)
	{
		const qint64 bytesToCopy(qMin(qint64(m_blockSize - m_writingBuffered), (length - position)));

		memcpy(&m_writingBuffer[m_writingBuffered], &data[position], bytesToCopy);

		m_writingBuffered += bytesToCopy;
		position += bytesToCopy;

		if (m_writingBuffered < m_blockSize)
		{
			break;
		}

		if (!writeBufferEncrypted())
		{
			return -1;
		}
	}

	return length;
}

bool EncryptedFile::writeBufferEncrypted()
{
	unsigned char ciphertext[MAXBLOCKSIZE] = {};

	if (ctr_encrypt(m_writingBuffer, ciphertext, m_writingBuffered, &m_ctr) != CRYPT_OK)
	{
		m_isValid = false;

		return false;
	}

	if (m_device->write(reinterpret_cast<const char*>(ciphertext), m_writingBuffered) != m_writingBuffered)
	{
		m_isValid = false;

		return false;
	}

	if (m_writingBuffered != m_blockSize)
	{
		m_isValid = false;
	}

	m_writingBuffered = 0;

	return true;
}

void EncryptedFile::initReading()
{
	unsigned char initializationVector[MAXBLOCKSIZE] = {};
	char header[sizeof m_header] = {};

	if ((m_device->read(header, sizeof m_header) != sizeof m_header) || memcmp(m_header, header, sizeof m_header))
	{
		m_isValid = false;

		return;
	}

	if (m_device->read(reinterpret_cast<char*>(initializationVector), m_initializationVectorSize) != m_initializationVectorSize)
	{
		m_isValid = false;

		return;
	}

	if (ctr_start(m_cipherIndex, initializationVector, m_key, m_keySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &m_ctr) != CRYPT_OK)
	{
		m_isValid = false;

		return;
	}
}

void EncryptedFile::initWriting()
{
	prng_state prng;
	unsigned char initializationVector[MAXBLOCKSIZE] = {};

	rng_make_prng(128, find_prng("yarrow"), &prng, NULL);

	const int randomBytesRead(yarrow_read(initializationVector, m_initializationVectorSize, &prng));

	if (randomBytesRead != m_initializationVectorSize)
	{
		m_isValid = false;

		return;
	}

	if (ctr_start(m_cipherIndex, initializationVector, m_key, m_keySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &m_ctr) != CRYPT_OK)
	{
		m_isValid = false;

		return;
	}

	if (m_device->write(m_header, sizeof m_header) != sizeof m_header)
	{
		m_isValid = false;

		return;
	}

	if (m_device->write(reinterpret_cast<const char*>(initializationVector), m_initializationVectorSize) != m_initializationVectorSize)
	{
		m_isValid = false;

		return;
	}
}
