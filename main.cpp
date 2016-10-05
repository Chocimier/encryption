#include <QString>
#include <QFile>

#include "CustomDevice.h"
#include "EncryptedFile.h"

int main()
{
	QString key("a");
	QList<CustomDevice::Feature> features{CustomDevice::Feature::Encryption};

	QFile sourceFile("EncryptedFile.cpp");
	QFile file("plik.enc");
	CustomDevice encryptor(&file, features);
	dynamic_cast<EncryptedFile*>(encryptor.getChainDevice(0))->setKey(key.toUtf8());

	sourceFile.open(QIODevice::ReadOnly);
	encryptor.open(QIODevice::WriteOnly);

	encryptor.write(sourceFile.readAll());

	encryptor.close();
	sourceFile.close();

	QFile file2("plik.enc");
	QFile file3("plik.dec");
	CustomDevice decryptor(&file2, features);
	dynamic_cast<EncryptedFile*>(decryptor.getChainDevice(0))->setKey(key.toUtf8());

	decryptor.open(QIODevice::ReadOnly);
	file3.open(QIODevice::WriteOnly);

	file3.write(decryptor.readAll());

	decryptor.close();
	sourceFile.close();

	return 0;
}
