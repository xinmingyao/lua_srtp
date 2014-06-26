LUALIB_MINGW=-I/usr/local/include -L/usr/local/bin -llua52  -llibsrtp
SRTP = -I../libsrtp/include -I../libsrtp/crypto/include -L../libsrtp/  -lsrtp
SRC=\
src/lua_srtp.c


all :
	echo 'make win or make posix or make macosx'

win : lua_srtp.dll lua_srtp.lib
posix : lua_srtp.so
macosx: lua_srtp.dylib

lua_srtp.so : $(SRC)
	gcc -g -Wall --shared -fPIC -o $@ $^ $(SRTP) -lpthread 

lua_srtp.dll : $(SRC)
	gcc -g -Wall -D_GUI --shared -o $@ $^ $(LUALIB_MINGW) -L./lua52  -march=i686 -lws2_32

lua_srtp.dylib : $(SRC)
	gcc -g -Wall -bundle -undefined dynamic_lookup -fPIC -o $@ $^ -lpthread

clean :
	rm -rf lua_srtp.dll lua_srtp.so lua_srtp.dylib lua_srtp.dylib.dSYM lua_srtp.lib
lua_srtp.lib :
	dlltool -d lua_srtp.def -l lua_srtp.lib
