//go:build windows && cgo && pqopenssl

package main

// The same replay format and hash chain as Linux, but Windows opens the
// validated NTFS file with no sharing and write-through. No automatic repair.
func winInitReplay(path,sign,enc,app string)error{
 h,e:=replayBinding(sign,enc,app);if e!=nil{return e}
 return winWritePrivate(path,h)
}
func winOpenReplay(path,sign,enc,app string)(*replayLog,error){
 h,e:=replayBinding(sign,enc,app);if e!=nil{return nil,e}
 f,hs,e:=winOpenPrivateMode(path,2);if e!=nil{return nil,e}
 ok:=false
 defer func(){if !ok{f.Close();winClose(hs)}}()
 if e=lockReplay(f);e!=nil{return nil,e}
 st,e:=f.Stat();if e!=nil||!st.Mode().IsRegular(){return nil,windowsStorageRefusal}
 j,e:=parseReplayHandle(f,h,st.Size());if e!=nil{return nil,e}
 j.release=func(){winClose(hs)};j.resultWrite=winWritePrivate;j.resultRead=winReadPrivate;ok=true
 return j,nil
}
