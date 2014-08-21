add_library(libemulateHost SHARED pcap_wrapper.cpp ethernet.cpp ip.cpp tp.cpp scope_guard.cpp ip_utils.cpp split.cpp socket.cpp args.cpp to_string.cpp libemulateHost.cpp spawn_process.cpp int_utils.cpp wol.cpp)
target_link_libraries(libemulateHost ${PCAP_LIBRARIES})

add_executable(emulateHost emulateHost.cpp)
target_link_libraries(emulateHost libemulateHost)

find_package (Threads)
add_executable(watchHost watchHost.cpp)
target_link_libraries(watchHost ${CMAKE_THREAD_LIBS_INIT} libemulateHost)

add_executable(waker waker.cpp)
target_link_libraries(waker libemulateHost)

INSTALL(TARGETS libemulateHost emulateHost watchHost waker
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
