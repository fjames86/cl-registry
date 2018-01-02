;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:cl-registry
  (:use #:cl #:cffi)
  (:export #:win-error
	   #:reg-open-key
	   #:reg-close-key
	   #:with-reg-key
	   #:reg-create-key
	   #:reg-enum-key
	   #:reg-enum-value
	   #:reg-set-value
	   #:reg-delete-value
	   #:reg-set-key-value
	   #:reg-delete-tree
	   #:reg-get-value
	   
	   #:reg
	   #:create-key
	   #:remove-key
	   #:set-reg-value)
  (:nicknames #:reg))

(in-package #:cl-registry)

(define-foreign-library advapi
  (:windows "Advapi32.dll"))

(use-foreign-library advapi)

;; for errors
(defcfun (%format-message "FormatMessageA" :convention :stdcall)
    :uint32
  (flags :uint32)
  (source :pointer)
  (msg-id :uint32)
  (lang-id :uint32)
  (buffer :pointer)
  (size :uint32)
  (args :pointer))

(defun format-message (code)
  "Use FormatMessage to convert the error code into a system-defined string."
  (with-foreign-object (buffer :char 1024)
    (let ((n (%format-message #x00001000
			      (null-pointer)
			      code
			      0
			      buffer
			      1024
			      (null-pointer))))
      (if (= n 0)
	  (error "Failed to format message")
	  (foreign-string-to-lisp buffer :count (- n 2))))))

(define-condition win-error (error)
  ((code :initform 0 :initarg :code :reader win-error-code))
  (:report (lambda (condition stream)
	     (format stream "ERROR ~A: ~A" 
		     (win-error-code condition)
		     (format-message (win-error-code condition))))))
	   
		   
;; --------- registry API ------------------

(defctype hkey :uint32)


(defcfun (%reg-open-key "RegOpenKeyExA" :convention :stdcall)
    :uint32
  (key hkey)
  (name :string)
  (options :uint32)
  (desired :uint32)
  (result :pointer))

(defparameter *hkey-trees* 
  '((:classes-root . 2147483648) 
    (:hkcr . 2147483648)     
    (:current-user . 2147483649)
    (:hkcu . 2147483649) 
    (:local-machine . 2147483650)
    (:hklm . 2147483650) 
    (:users . 2147483651)
    (:hkuser . 2147483651) 
    (:current-config . 2147483653)
    (:hkcc . 2147483653)))

(defun resolve-key (key)
  (etypecase key
    (keyword (cdr (assoc key *hkey-trees*)))
    (integer key)))

(defconstant +desire-all-access+ #xf003f)
(defconstant +desire-key-read+ #x20019)

(defun reg-open-key (name &key key (options 0) (desired +desire-all-access+))
  "Open the registry key named by NAME, which lives under the key named by KEY."
  (with-foreign-object (handle 'hkey)
    (let ((sts (%reg-open-key (resolve-key key)
			      (or name (cffi:null-pointer))
			      options 
			      (cond
				((symbolp desired)
				 (ecase desired
				   (:read +desire-key-read+)
				   (:all +desire-all-access+)))
				((integerp desired)
				 desired)
				(t (error "must be integer or :read or :all")))
			      handle)))
      (if (zerop sts)
	  (mem-ref handle 'hkey)
	  (error 'win-error :code sts)))))

(defcfun (reg-close-key "RegCloseKey" :convention :stdcall)
    :long
  (key hkey))


(defmacro with-reg-key ((var name &key key desired ) &body body)
  `(let ((,var (reg-open-key ,name :key ,key :desired ,(or desired :read))))
     (unwind-protect (progn ,@body)
       (reg-close-key ,var))))

(defcfun (%reg-create-key "RegCreateKeyExA" :convention :stdcall)
    :long
  (key hkey)
  (name :string)
  (reserved :uint32)
  (class :string)
  (options :uint32)
  (desired :uint32)
  (attributes :pointer)
  (result :pointer)
  (disposition :pointer))

(defun reg-create-key (name &key key (options 0) (desired +desire-all-access+))
  "Create a new registry key named NAME underneath the key KEY."
  (with-foreign-object (handle 'hkey)
    (let ((res (%reg-create-key (resolve-key key)
				name 
				0
				(null-pointer)
				options
				desired
				(null-pointer)
				handle
				(null-pointer))))
      (if (= res 0)
	  (mem-ref handle 'hkey)
	  (error 'win-error :code res)))))

(defcfun (%reg-enum-key "RegEnumKeyExA" :convention :stdcall)
    :long
  (key hkey)
  (index :uint32)
  (name-buffer :pointer)
  (name-size :pointer)
  (reserved :pointer)
  (class :pointer)
  (class-size :pointer)
  (last-write :pointer))

(defun reg-enum-key (key &optional tree)
  "Return a list of all subkeys of the key named by KEY. KEY can be a key handle, as returned by REG-OPEN-KEY, or a string naming a key, with TREE a keyword naming a top-level registry tree."
  (if (stringp key)
      (with-reg-key (k key :key tree)
	(reg-enum-key k))
      (with-foreign-object (buffer :char 1024)
	(with-foreign-object (size :uint32)
	  (do ((i 0 (1+ i))
	       (names nil)
	       (done nil))
	      (done names)
	    (setf (mem-ref size :uint32) 1024)
	    (let ((res (%reg-enum-key (resolve-key key)
				      i
				      buffer
				      size
				      (null-pointer)
				      (null-pointer)
				      (null-pointer)
				      (null-pointer))))
	      (if (= res 0)
		  (push (foreign-string-to-lisp buffer :count (mem-ref size :uint32))
			names)
		  (setf done t))))))))

				  

(defcfun (%reg-enum-value "RegEnumValueA" :convention :stdcall)
    :long
  (key hkey)
  (index :uint32)
  (name :pointer)
  (size :pointer)
  (reserved :pointer)
  (type :pointer)
  (data :pointer)
  (data-size :pointer))

(defparameter *reg-types*
  '((:string 1)
    (:expand-string 2)
    (:binary 3)
    (:dword 4)
    (:multi-string 7)))

(defun reg-enum-value (key &optional tree)
  "List all the values of the registry key."
  (if (stringp key)
      (with-reg-key (k key :key tree)
	(reg-enum-value k))
      (with-foreign-objects ((name-buffer :char 1024)
			     (size :uint32)
			     (data :char 1024)
			     (data-size :uint32)
			     (type :uint32))
	(do ((i 0 (1+ i))
	     (vals nil)
	     (done nil))
	    (done vals)
	  (setf (mem-ref size :uint32) 1024
		(mem-ref data-size :uint32) 1024)
	  (let ((res (%reg-enum-value (resolve-key key)
				      i
				      name-buffer
				      size
				      (null-pointer)
				      type
				      data
				      data-size)))
	    (if (= res 0)
		(push 
		 (let ((vec (make-array (mem-ref data-size :uint32)
					:element-type '(unsigned-byte 8)))
		       (rtype (first 
			       (find (mem-ref type :uint32)
				     *reg-types*
				     :key #'second))))
		   (dotimes (i (mem-ref data-size :uint32))
		     (setf (aref vec i) (mem-ref data :uint8 i)))
		   (list (foreign-string-to-lisp name-buffer 
						 :count (mem-ref size :uint32))
			 (case rtype
			   ((:string :expand-string) (babel:octets-to-string vec :end (position 0 vec)))
			   (:dword (nibbles:ub32ref/le vec 0))
			   (t vec))
			 rtype))
		 vals)
		(setf done t)))))))

(defcfun (%reg-set-value "RegSetValueExA" :convention :stdcall)
    :long
  (key hkey)
  (name :pointer)
  (reserved :uint32)
  (type :uint32)
  (data :pointer)
  (size :uint32))

(defun reg-set-value (key name data type)
  "Set the registry value. Data should be an octet vector, type should be a keyword."
  (declare (type vector data)
	   (type symbol type)
	   (type string name))
  (let ((length (length data)))
    (with-foreign-object (buffer :uint8 length)
      (with-foreign-string (nstr name)
	(dotimes (i length)
	  (setf (mem-ref buffer :uint8 i)
		(aref data i)))
	(let ((res (%reg-set-value (resolve-key key)
				   nstr
				   0
				   (second 
				    (find type *reg-types*
					  :key #'first))
				   buffer
				   length)))
	  (if (= res 0)
	      nil
	      (error 'win-error :code res)))))))

(defcfun (%reg-delete-value "RegDeleteValueA" :convention :stdcall)
   :long
  (key hkey)
  (name :string))

(defun reg-delete-value (key name)
  "Delete a registry value."
  (with-foreign-string (nstr name)
    (let ((res (%reg-delete-value key nstr)))
      (if (= res 0)
	  nil
	  (error 'win-error :code res)))))

(defcfun (%reg-set-key-value "RegSetKeyValueA" :convention :stdcall)
    :long
  (key hkey)
  (subkey :string)
  (name :string)
  (type :uint32)
  (data :pointer)
  (length :uint32))

(defun reg-set-key-value (key name data &key subkey (type :string))
  "Set a registry value underneath subkey SUBKEY."
  (let ((length (length data)))
    (with-foreign-object (buffer :uint8 length)
      (with-foreign-strings ((nstr name)
			     (skstr (or subkey "")))
	(let ((res (%reg-set-key-value (resolve-key key)
				       (if subkey skstr (null-pointer))
				       nstr
				       (second (find type *reg-types* :key #'first))
				       buffer
				       length)))
	  (if (= res 0)
	      nil
	      (error 'win-error :code res)))))))


(defcfun (%reg-delete-tree "RegDeleteTreeA" :convention :stdcall)
    :long
  (key hkey)
  (subkey :string))

(defun reg-delete-tree (key &optional subkey)
  "Delete a registry key and all its subkeys/values."
  (with-foreign-string (skstr (or subkey ""))
    (let ((res (%reg-delete-tree (resolve-key key)
				 (if subkey skstr (null-pointer)))))
      (if (= res 0)
	  nil
	  (error 'win-error :code res)))))

(defcfun (%reg-get-value "RegGetValueA" :convention :stdcall)
    :long
  (key hkey)
  (subkey :string)
  (name :string)
  (flags :uint32)
  (type :pointer)
  (data :pointer)
  (size :pointer))

(defun reg-get-value (key name &optional subkey)
  "Get a registry value."
  (if (and subkey (stringp subkey))
      (with-reg-key (k subkey :key key)
	(reg-get-value k name))
      (with-foreign-strings ((nstr name)
			     (skstr (or subkey "")))
	(with-foreign-objects ((buffer :uint8 1024)
			       (sbuff :uint32)
			       (tbuff :uint32))
	  (setf (mem-ref sbuff :uint32) 1024)
	  (let ((res 
		 (%reg-get-value (resolve-key key)
				 (if subkey skstr (null-pointer))
				 nstr
				 #xffff ;; any data type
				 tbuff
				 buffer
				 sbuff)))
	    (if (= res 0)
		(values 
		 (let ((v (make-array (mem-ref sbuff :uint32) :element-type '(unsigned-byte 8))))
		   (dotimes (i (mem-ref sbuff :uint32))
		     (setf (aref v i) (mem-ref buffer :uint8 i)))
		   v)
		 (first (find (mem-ref tbuff :uint32) *reg-types* :key #'second)))
		(error 'win-error :code res)))))))




(defun parse-hive (key)
  (let ((pos (position #\\ key :test #'char=)))
    (values (let ((k (if pos
			 (subseq key 0 pos)
			 key)))
	      (cond
		  ((string-equal k "HKLM") :hklm)
		  ((string-equal k "HKCU") :hkcu)
		  ((string-equal k "HKCR") :hkcr)
		  ((string-equal k "HKCC") :hkcc)
		  ((string-equal k "HKUSER") :hkuser)
		  (t (error "Unknown hive ~S" k))))
	    (if pos
		(subseq key (1+ pos))
		nil))))

(defun reg (key &optional no-subkeys-p no-values-p)
  "Enumerate all subkeys and values of the given KEY. Key must begin with 
hive identifier HKLM, HKCU, HKCR, HKCC, HKUSER.

NO-SUBKEYS-P ::= if true do not enumerate subkeys.
NO-VALUES-P ::= if true do not enumerate values.

Values are returned as a list of 3 elements: name value type
where type is a keyword from :dword, :string, :binary :multi-string, :expand-string.

"
  (multiple-value-bind (hive path) (parse-hive key)
    (with-reg-key (k path :key hive :desired :read)
      (append (unless no-subkeys-p (reg-enum-key k))
	      (unless no-values-p (reg-enum-value k))))))

(defun set-reg-value (key name value &optional type)
  (multiple-value-bind (hive path) (parse-hive key)
    (with-reg-key (k path :key hive :desired :read)
      (let* ((tname (if (null type)
			(cond 
			  ((stringp value) :string)
			  ((vectorp value) :binary)
			  ((integerp value) :dword)
			  (t (error "Value must be string integer or octet vector")))
			type))
	     (vec (ecase tname
		    ((:string :expand-string :multi-string)
		     (babel:string-to-octets value))
		    (:dword (let ((v (nibbles:make-octet-vector 4)))
			      (setf (nibbles:ub32ref/le v 0) value)
			      v))
		    (:binary value))))
	(reg-set-value k
		       name
		       vec
		       tname)))))

(defun create-key (name parentkey)
  (multiple-value-bind (hive path) (parse-hive parentkey)
    (with-reg-key (k path :key hive :desired :all)
      (reg-create-key name :key k))))

(defun remove-key (name)
  (multiple-value-bind (hive path) (parse-hive name)
    (with-reg-key (k path :key hive :desired :all)
      (reg-delete-tree k))))

