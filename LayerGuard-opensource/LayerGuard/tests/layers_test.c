#include <stdio.h>
#include <assert.h>
#include "layers.h"
int main(void){
  assert(LgCheckTransition(0,0)==LG_POL_SAME);
  assert(LgCheckTransition(0,15)==LG_POL_RESERVED);
  assert(LgCheckTransition(14,15)==LG_POL_RESERVED);
  assert(LgCheckTransition(0,5)==LG_POL_JUMP);
  assert(LgCheckTransition(0,4)==LG_POL_OK);
  assert(LgCheckTransition(9,1)==LG_POL_OK);
  assert(LgCheckTransition(-1,3)==LG_POL_RANGE && LgCheckTransition(0,16)==LG_POL_RANGE);
  assert(!LgNeedsAuth(7,3) && LgNeedsAuth(3,7));
  for(int i=0;i<LG_LAYER_COUNT;i++){ const LgLayer*L=LgGetLayer(i); assert(L&&L->id==i); }
  assert(LgGetLayer(0)->iso==LG_ISO_APPCONTAINER && LgGetLayer(15)->iso==LG_ISO_RESERVED);
  assert(LgGetLayer(0)->flags==0 && (LgGetLayer(3)->flags&LG_F_NET));
  puts("layers policy: all assertions passed");
  return 0; }
