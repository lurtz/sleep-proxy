find_package (Threads)
add_library(sleep-proxy SHARED pcap_wrapper.cpp ethernet.cpp ip.cpp tp.cpp scope_guard.cpp ip_utils.cpp split.cpp socket.cpp args.cpp to_string.cpp libsleep_proxy.cpp spawn_process.cpp int_utils.cpp wol.cpp packet_parser.cpp)
target_link_libraries(sleep-proxy ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

add_executable(emulateHost emulateHost.cpp)
target_link_libraries(emulateHost sleep-proxy)

add_executable(watchHost watchHost.cpp)
target_link_libraries(watchHost sleep-proxy)

add_executable(waker waker.cpp)
target_link_libraries(waker sleep-proxy)

add_executable(sniffer sniffer.cpp)
target_link_libraries(sniffer sleep-proxy)

INSTALL(TARGETS sleep-proxy emulateHost watchHost waker sniffer
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
