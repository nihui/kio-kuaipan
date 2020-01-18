project(kio-kuaipan)
cmake_minimum_required(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
find_package(KDE4 REQUIRED 4.4)
find_package(QJson REQUIRED)
find_package(QCA2 REQUIRED)
find_package(QtOAuth REQUIRED)

include(KDE4Defaults)

add_definitions(${QT_DEFINITIONS} ${KDE4_DEFINITIONS})
include_directories(${KDE4_INCLUDES} ${QT_INCLUDES})
include_directories(${QCA2_INCLUDE_DIR} ${QTOAUTH_INCLUDE_DIR})

set(kio_kuaipan_SRCS
    kuaipan.cpp
    multipartdevice.cpp
)

kde4_add_plugin(kio_kuaipan ${kio_kuaipan_SRCS})

target_link_libraries(kio_kuaipan
    ${KDE4_KDECORE_LIBS}
    ${KDE4_KIO_LIBS}
    ${QCA2_LIBRARIES}
    ${QTOAUTH_LIBRARY}
    ${QJSON_LIBRARY}
)

install(TARGETS kio_kuaipan DESTINATION ${PLUGIN_INSTALL_DIR})
install(FILES kuaipan.protocol DESTINATION ${SERVICES_INSTALL_DIR})
