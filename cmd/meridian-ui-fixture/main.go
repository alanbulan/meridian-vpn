//go:build meridian_uifixture

package main
import (
 "log"
 "os"
 "path/filepath"
 "github.com/egoist/mygo"
 "github.com/egoist/mygo/ui"
 "mygo-vpn/internal/desktop"
)
func main(){
 dir,err:=os.MkdirTemp("","meridian-ui-preview-");if err!=nil{log.Fatal(err)};defer os.RemoveAll(dir)
 a:=desktop.AuthenticationPreview(filepath.Join(dir,"unused.json"))
 mygo.App.WhenReady(func(){a.Window=mygo.NewWindow(mygo.WindowOptions{Title:"Meridian 认证界面测试 · 不联网",Width:960,Height:620,MinWidth:880,MinHeight:580,Content:ui.View(a.View)});a.Window.OnClose(func(e *mygo.CloseEvent){mygo.App.Quit()})})
 if err:=mygo.App.Run();err!=nil{log.Fatal(err)}
}
