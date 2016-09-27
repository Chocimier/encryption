cmake_minimum_required(VERSION 2.8)

set(CMP0065 NEW)
set(ENABLE_EXPORTS OFF)

set(project_name crypt-device)
set(project_src
	main.cpp
	EncryptedFile.cpp
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

add_executable(${project_name} ${project_src} ${ui} ${res})
qt5_use_modules(${project_name} ${qt_modules})
target_link_libraries(${project_name} tomcrypt)
set_property(TARGET ${project_name} PROPERTY CXX_STANDARD 11)
