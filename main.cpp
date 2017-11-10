#include <QString>
#include <QFile>

#include "CustomDevice.h"
#include "EncryptionDevice.h"

int main()
{
	QString key("a");

	QFile sourceFile("EncryptionDevice.cpp");
	QFile file("plik.enc");
	EncryptionDevice encryptor(&file);
	encryptor.setKey(key.toUtf8());

	sourceFile.open(QIODevice::ReadOnly);
	encryptor.open(QIODevice::WriteOnly);

	encryptor.write(sourceFile.readAll());

	encryptor.close();
	sourceFile.close();

	QFile file2("plik.enc");
	QFile file3("plik.dec");
	EncryptionDevice decryptor(&file2);
	decryptor.setKey(key.toUtf8());

	decryptor.open(QIODevice::ReadOnly);
	file3.open(QIODevice::WriteOnly);

	file3.write(decryptor.readAll());

	decryptor.close();
	sourceFile.close();

	return 0;
}
