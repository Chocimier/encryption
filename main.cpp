#include <QString>
#include <QFile>

#include "EncryptedFile.h"

int main(int argc, char *argv[])
{
	QFile file("plik.enc");
	EncryptedFile encryptor(&file);
	encryptor.setKey(QString("klucz\n").toUtf8());
	encryptor.open(QIODevice::WriteOnly | QIODevice::Text);

	for(int i = 0; i <= 1000; ++i)
	{
		encryptor.write(QString::number(i).toUtf8() + "\n");
	}

	encryptor.close();

	return 0;
}
