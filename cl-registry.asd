;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(asdf:defsystem :cl-registry
  :name "CL-Registry"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "Bindings to Windows registry API"
  :license "MIT"
  :components
  ((:file "registry"))
  :depends-on (:cffi :cl-ppcre))



