CXX=clang++
LD=clang++
CXXFLAGS=-O2 -fPIC -I../dynamorio/include -I../dynamorio/ext/include -DX86_64 -DLINUX -fno-stack-protector
LDFLAGS=-Wl,-hash-style=both ../dynamorio/lib64/debug/libdynamorio.so ../dynamorio/ext/lib64/debug/libdrsyms.so ../dynamorio/ext/lib64/debug/libdrmgr.so 
DEPS=common.h
SRCS=drsancov.cc common.cc tokenizer.cc
OBJS=$(subst .cc,.o,$(SRCS))

all: libdrsancov.so

%.o: %.cc $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

libdrsancov.so: $(OBJS)
	$(LD) -shared -o $@ $(OBJS) $(LDFLAGS)

clean:
	$(RM) libdrsancov.so $(OBJS)
