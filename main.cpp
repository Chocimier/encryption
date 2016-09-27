#include <QString>

#include "EncryptedFile.h"

int main(int argc, char *argv[])
{
	EncryptedFile file("./plik.enc", NULL);
	file.setKey(QString("klucz\n").toUtf8());
	file.open(QIODevice::WriteOnly | QIODevice::Text);

	for(int i = 0; i <= 1000; ++i)
	{
		file.write(QString::number(i).toUtf8() + "\n");
	}

	file.close();

	return 0;
}
