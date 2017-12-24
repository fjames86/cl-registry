# cl-registry
CFFI bindings to Windows registry API

This package provides a low level wrapper over the Windows registry API.

```
;; open a key and enumerate its subkeys
(with-reg-key (k "SOFTWARE" :key :local-machine)
  (reg-enum-key k))

;; equivalent to 
(reg-enum-key "SOFTWARE" :tree :local-machine)
```

```
;; enumerate all values
(reg-enum-value "SOFTWARE\\Microsoft" :tree :local-machine)
```

;; Easier
```
(reg "HKLM")
(reg "HKLM\\Software")
```


