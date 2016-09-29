cmake_minimum_required(VERSION 2.8)

set(project_name crypt-device)
set(project_src
	main.cpp
	EncryptedFile.cpp
	libtomcrypt/hashes/sha2/sha256.c
	libtomcrypt/hashes/helper/hash_memory.c
	libtomcrypt/prngs/rng_make_prng.c
	libtomcrypt/prngs/yarrow.c
	libtomcrypt/prngs/sprng.c
	libtomcrypt/prngs/rng_get_bytes.c
	libtomcrypt/prngs/fortuna.c
	libtomcrypt/ciphers/aes/aes.c
	libtomcrypt/ciphers/aes/aes_tab.c
	libtomcrypt/modes/cbc/cbc_setiv.c
	libtomcrypt/modes/cbc/cbc_decrypt.c
	libtomcrypt/modes/cbc/cbc_encrypt.c
	libtomcrypt/modes/cbc/cbc_done.c
	libtomcrypt/modes/cbc/cbc_getiv.c
	libtomcrypt/modes/cbc/cbc_start.c
	libtomcrypt/modes/ctr/ctr_done.c
	libtomcrypt/modes/ctr/ctr_getiv.c
	libtomcrypt/modes/ctr/ctr_test.c
	libtomcrypt/modes/ctr/ctr_start.c
	libtomcrypt/modes/ctr/ctr_encrypt.c
	libtomcrypt/modes/ctr/ctr_setiv.c
	libtomcrypt/modes/ctr/ctr_decrypt.c
	libtomcrypt/misc/crypt/crypt_cipher_descriptor.c
	libtomcrypt/misc/crypt/crypt_argchk.c
	libtomcrypt/misc/crypt/crypt_prng_is_valid.c
	libtomcrypt/misc/crypt/crypt_register_prng.c
	libtomcrypt/misc/crypt/crypt_find_prng.c
	libtomcrypt/misc/crypt/crypt_prng_descriptor.c
	libtomcrypt/misc/crypt/crypt_cipher_is_valid.c
	libtomcrypt/misc/crypt/crypt_register_cipher.c
	libtomcrypt/misc/crypt/crypt_hash_is_valid.c
	libtomcrypt/misc/crypt/crypt_find_cipher.c
	libtomcrypt/misc/crypt/crypt_register_hash.c
	libtomcrypt/misc/crypt/crypt_find_hash.c
	libtomcrypt/misc/crypt/crypt_hash_descriptor.c
	libtomcrypt/misc/zeromem.c
)
set(project_ui
)
set(project_res
)
set(qt_modules Core)
set(qt_required_version 5)

project(${project_name})
find_package(Qt5 ${qt_required_version} REQUIRED COMPONENTS ${qt_modules})

list(FIND qt_modules "Widgets" widgets_index)
string(COMPARE NOTEQUAL ${widgets_index} "-1" using_widgets)
if(${using_widgets})
	qt5_wrap_ui(ui
		${project_ui}
	)
endif()

qt5_add_resources(res
	${project_res}
)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

add_definitions(-DLTC_SOURCE -DLTC_NO_PROTOTYPES)
include_directories(libtomcrypt/headers)
add_executable(${project_name} ${project_src} ${ui} ${res})
qt5_use_modules(${project_name} ${qt_modules})
set_property(TARGET ${project_name} PROPERTY CXX_STANDARD 11)
