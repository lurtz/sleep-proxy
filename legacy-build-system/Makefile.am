sources = ../src/pcap_wrapper.cpp ../src/ethernet.cpp ../src/ip.cpp ../src/tp.cpp ../src/scope_guard.cpp ../src/ip_utils.cpp ../src/split.cpp ../src/socket.cpp ../src/args.cpp ../src/to_string.cpp ../src/libemulateHost.cpp ../src/spawn_process.cpp ../src/int_utils.cpp ../src/wol.cpp

bin_PROGRAMS = emulateHost watchHost waker
emulateHost_LDFLAGS = -lpcap
emulateHost_SOURCES = ../src/emulateHost.cpp $(sources)
watchHost_LDFLAGS = -lpcap $(PTHREAD_CFLAGS)
watchHost_SOURCES = ../src/watchHost.cpp $(sources)
waker_SOURCES = ../src/waker.cpp ../src/wol.cpp ../src/ip_utils.cpp ../src/int_utils.cpp ../src/to_string.cpp ../src/socket.cpp ../src/split.cpp
