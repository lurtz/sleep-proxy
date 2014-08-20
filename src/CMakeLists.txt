add_library(libemulateHost pcap_wrapper.cpp ethernet.cpp ip.cpp tp.cpp scope_guard.cpp ip_utils.cpp split.cpp socket.cpp args.cpp to_string.cpp libemulateHost.cpp spawn_process.cpp int_utils.cpp wol.cpp)

add_executable(emulateHost emulateHost.cpp)
target_link_libraries(emulateHost ${PCAP_LIBRARIES} libemulateHost)

find_package (Threads)
add_executable(watchHost watchHost.cpp)
target_link_libraries(watchHost ${CMAKE_THREAD_LIBS_INIT} ${PCAP_LIBRARIES} libemulateHost)

add_executable(waker waker.cpp)
target_link_libraries(waker libemulateHost)
