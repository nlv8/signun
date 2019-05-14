#!/usr/bin/env sh
# From: https://github.com/cryptocoinjs/secp256k1-node
# The MIT License (MIT)
# 
# Copyright (c) 2014-2016 secp256k1-node contributors
# 
# Parts of this software are based on bn.js, elliptic, hash.js
# Copyright (c) 2014-2016 Fedor Indutny
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
has_lib() {
  local regex="lib$1.+(so|dylib)"

  # Add /sbin to path as ldconfig is located there on some systems - e.g. Debian
  # (and it still can be used by unprivileged users):
  PATH="$PATH:/sbin"
  export PATH

  # Try just checking common library locations
  for dir in /lib /usr/lib /usr/local/lib /opt/local/lib /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu; do
    test -d $dir && echo "$(ls $dir)" | grep -E $regex && return 0
  done

  return 1
}

has_lib $1 > /dev/null
if test $? -eq 0; then
  echo true
else
  echo false
fi
