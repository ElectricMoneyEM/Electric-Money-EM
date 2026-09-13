# V20.4 architecture note

V20.4 performs a complete source partition of the V19.2 reference by domain. To preserve consensus behavior exactly, class/member implementations remain in their owning module headers and are compiled through independent translation units. This is intentional: moving inline member bodies to out-of-class definitions is a separate ABI-neutral cleanup and must be accompanied by differential consensus tests.

The legacy V19.2 file remains available solely as a reference oracle. It is not included in the V20.4 executable.
