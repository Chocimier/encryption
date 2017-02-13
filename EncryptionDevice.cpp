#include "EncryptionDevice.h"

#include <cstring>

const char *EncryptionDevice::m_header("otter.aes\n1\n");
int EncryptionDevice::m_headerSize(std::strlen(m_header));
int EncryptionDevice::m_PKCSIterationCount = 100;
int EncryptionDevice::m_PKCSSaltSize = 128;
int EncryptionDevice::m_PKCSResultSize = 256;
int EncryptionDevice::m_ctrMode = CTR_COUNTER_LITTLE_ENDIAN;

EncryptionDevice::EncryptionDevice(QIODevice *targetDevice, QObject *parent) : QIODevice(parent),
	m_device(targetDevice),
	m_readingBuffered(0),
	m_blockSize(16),
	m_initializationVectorSize(16),
	m_keySize(32),
	m_writingBuffered(0),
	m_hasPlainKey(false),
	m_isValid(true),
	m_readAll(false)
{
	register_cipher(&aes_desc);
	register_hash(&sha256_desc);

	m_cipherIndex = find_cipher("aes");
	m_hashIndex = find_hash("sha256");

	m_isValid &= (m_cipherIndex != -1);
	m_isValid &= (m_hashIndex != -1);

	if (!m_isValid)
	{
		return;
	}

	m_isValid &= (register_prng(&fortuna_desc) != -1);
	m_isValid &= (register_prng(&sprng_desc) != -1);
	m_isValid &= (m_keySize == hash_descriptor[m_hashIndex].hashsize);
	m_isValid &= (m_blockSize == cipher_descriptor[m_cipherIndex].block_length);
	m_isValid &= (m_initializationVectorSize == cipher_descriptor[m_cipherIndex].block_length);
	m_isValid &= (cipher_descriptor[m_cipherIndex].keysize(&m_keySize) == CRYPT_OK);
}

void EncryptionDevice::close()
{
	if (openMode().testFlag(QIODevice::WriteOnly))
	{
		writeBufferEncrypted();

		m_device->close();

		setOpenMode(m_device->openMode());
	}

	m_isValid = false;
}

bool EncryptionDevice::isSequential() const
{
	return true;
}

bool EncryptionDevice::open(QIODevice::OpenMode mode)
{
	if (isOpen())
	{
		return true;
	}

	if (!m_isValid || !m_hasPlainKey || mode.testFlag(QIODevice::ReadWrite) || mode.testFlag(QIODevice::Append) || mode.testFlag(QIODevice::Text) || !m_device->open(mode))
	{
		return false;
	}

	setOpenMode(m_device->openMode());

	if (mode.testFlag(QIODevice::ReadOnly))
	{
		initializeReading();
	}
	else if (mode.testFlag(QIODevice::WriteOnly))
	{
		initializeWriting();
	}

	if (!m_isValid)
	{
		m_device->close();

		setOpenMode(m_device->openMode());

		return false;
	}

	return true;
}

void EncryptionDevice::setKey(const QByteArray &plainKey)
{
	m_plainKey = plainKey;
	m_hasPlainKey = true;
}

void EncryptionDevice::initializeReading()
{
	char header[m_headerSize]{};
	unsigned char salt[m_PKCSSaltSize]{};

	m_isValid &= (m_device->read(header, m_headerSize) == m_headerSize);
	m_isValid &= !memcmp(m_header, header, m_headerSize);
	m_isValid &= (m_device->read(reinterpret_cast<char*>(salt), sizeof salt) == sizeof salt);
	m_isValid &= applyPKCS(salt);
	m_isValid &= (ctr_start(m_cipherIndex, m_initializationVector, m_key, m_keySize, 0, m_ctrMode, &m_ctr) == CRYPT_OK);
}

void EncryptionDevice::initializeWriting()
{
	unsigned char salt[m_PKCSSaltSize]{};
	prng_state prng;
	const int entropy(128);

	rng_make_prng(entropy, find_prng("fortuna"), &prng, NULL);

	const int randomBytesRead(fortuna_read(salt, sizeof salt, &prng));

	m_isValid &= (randomBytesRead == sizeof salt);
	m_isValid &= applyPKCS(salt);
	m_isValid &= (ctr_start(m_cipherIndex, m_initializationVector, m_key, m_keySize, 0, m_ctrMode, &m_ctr) == CRYPT_OK);
	m_isValid &= (m_device->write(m_header, m_headerSize) == m_headerSize);
	m_isValid &= (m_device->write(reinterpret_cast<const char*>(salt), sizeof salt) == sizeof salt);
}

qint64 EncryptionDevice::readData(char *data, qint64 length)
{
	unsigned char ciphertext[m_blockSize]{};
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

qint64 EncryptionDevice::writeData(const char *data, qint64 length)
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

bool EncryptionDevice::writeBufferEncrypted()
{
	unsigned char ciphertext[m_blockSize]{};

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

bool EncryptionDevice::applyPKCS(const unsigned char *salt)
{
	unsigned char PKCSResult[m_PKCSResultSize]{};
	unsigned long outputLength(sizeof PKCSResult);

	if (pkcs_5_alg2(reinterpret_cast<const unsigned char*>(m_plainKey.constData()), m_plainKey.size(), salt, m_PKCSSaltSize, m_PKCSIterationCount, m_hashIndex, PKCSResult, &outputLength) != CRYPT_OK)
	{
		return false;
	}

	memcpy(m_key, PKCSResult, m_keySize);
	memcpy(m_initializationVector, (PKCSResult + m_keySize), m_initializationVectorSize);

	return true;

}
