# Build script for the Falcon implementation.
#
# ==========================(LICENSE BEGIN)============================
#
# Copyright (c) 2017  Falcon Project
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ===========================(LICENSE END)=============================
#
# @author   Thomas Pornin <thomas.pornin@nccgroup.trust>

.POSIX:

EXPORTED = -s EXPORTED_FUNCTIONS=[\'_falcon_vrfy_new\',\'_falcon_vrfy_free\',\'_falcon_vrfy_set_public_key\',\'_falcon_vrfy_start\',\'_falcon_vrfy_update\',\'_falcon_vrfy_verify\',\'_falcon_sign_new\',\'_falcon_sign_free\',\'_falcon_sign_set_seed\',\'_falcon_sign_set_private_key\',\'_falcon_sign_start\',\'_falcon_sign_start_external_nonce\',\'_falcon_sign_update\',\'_falcon_sign_generate\',\'_falcon_keygen_new\',\'_falcon_keygen_free\',\'_falcon_keygen_max_privkey_size\',\'_falcon_keygen_max_pubkey_size\',\'_falcon_keygen_set_seed\',\'_falcon_keygen_make\'] 
EMFLAGS = -s EXTRA_EXPORTED_RUNTIME_METHODS=[\'addOnPostRun\',\'getValue\',\'setValue\'] $(EXPORTED)
#CC = c99
CFLAGS = -W -Wall -O #-pg -fno-pie
#LD = c99

LDFLAGS = 
LDLIBS = -lm

OBJ = falcon-enc.o falcon-vrfy.o frng.o shake.o falcon-fft.o falcon-keygen.o falcon-sign.o

all: test_falcon falcon

emscripten: falcon.bc
	$(LD) -o ../src/compiled.js falcon.bc $(EMFLAGS)
falcon.bc: api.o $(OBJ)
	$(LD) $(LDFLAGS) -o falcon.bc api.o $(OBJ) $(LDLIBS)
api.o:
	$(CC) $(CFLAGS) -c -o api.o api.c
clean:
	-rm -f $(OBJ) test_falcon test_falcon.o falcon api.o tool.o falcon.bc falcon.js falcon.wasm

test_falcon: test_falcon.o $(OBJ)
	$(LD) $(LDFLAGS) -o test_falcon test_falcon.o $(OBJ) $(LDLIBS)

falcon: tool.o $(OBJ)
	$(LD) $(LDFLAGS) -o falcon tool.o $(OBJ) $(LDLIBS)

test_falcon.o: test_falcon.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o test_falcon.o test_falcon.c

tool.o: tool.c falcon.h
	$(CC) $(CFLAGS) -c -o tool.o tool.c

falcon-enc.o: falcon-enc.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o falcon-enc.o falcon-enc.c

falcon-fft.o: falcon-fft.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o falcon-fft.o falcon-fft.c

falcon-keygen.o: falcon-keygen.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o falcon-keygen.o falcon-keygen.c

falcon-sign.o: falcon-sign.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o falcon-sign.o falcon-sign.c

falcon-vrfy.o: falcon-vrfy.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o falcon-vrfy.o falcon-vrfy.c

frng.o: frng.c falcon.h internal.h fpr-double.h shake.h
	$(CC) $(CFLAGS) -c -o frng.o frng.c

shake.o: shake.c shake.h
	$(CC) $(CFLAGS) -c -o shake.o shake.c
