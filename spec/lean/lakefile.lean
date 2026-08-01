import Lake

open Lake DSL

package zkguardSpec where
  buildDir := "../../.cache/lean-lake-build"

lean_lib ZkGuard
