package simpleauthmysql

import (
	"errors"
	"time"
	"net/http"
	"encoding/json"
	"github.com/lunny/log"
)

type DiagnosticsLog struct {
	EntryID   int64   `sql:"AUTO_INCREMENT" db:"entry_id" json:"entry_id" gorm:"column:entry_id;primary_key"`
	Added     int64   `sql:"not null" db:"added" json:"added,omitempty" gorm:"column:added"`
	Tag     string   `db:"type:varchar(100)" db:"tag" json:"tag" gorm:"column:tag"`
	Urgency int  `sql:"type:int(4);not null" gorm:"column:urgency"`
	EntryType int  `sql:"type:int(4);not null" gorm:"column:type"`
	RequestData string  `sql:"type:MEDIUMTEXT" gorm:"column:header"`
	Data      string  `sql:"type:MEDIUMTEXT" gorm:"column:data"`
	OtherData string  `sql:"type:MEDIUMTEXT" gorm:"column:other_data"`
}

const (
	DiagnosticsUrgencyTrace = 0
	DiagnosticsUrgencyNormal = 1
	DiagnosticsUrgencyNoteworthy = 10
	DiagnosticsUrgencyImportant = 25
	DiagnosticsUrgencyCritical = 50

	DiagnosticsTypeParser = 1
)

var diagnosticsReceiver chan *DiagnosticsLog

func AddDiagnosticsHeaderEntry(urgency int, entry_type int, header http.Header, tag string,data string){
	AddDiagnosticsHeaderEntryAndExtra(urgency, entry_type , header , tag ,data,"")
}

func AddDiagnosticsHeaderEntryAndExtra(urgency int, entry_type int, header http.Header, tag string,data string, extra string){
	header_bytes,err:=json.Marshal(header)
	var request_data string
	if err!=nil{
		request_data = err.Error()
	}else{
		request_data=string(header_bytes)
	}
	AddDiagnosticsLog(DiagnosticsLog{Added:time.Now().Unix(),Data:data,Tag:tag,EntryType:entry_type,RequestData:request_data,Urgency:urgency,OtherData:extra})
}

func AddDiagnosticsEntry(urgency int, entry_type int, data string){
	AddDiagnosticsLog(DiagnosticsLog{Added:time.Now().Unix(),Data:data,EntryType:entry_type,Urgency:urgency})
}

func AddDiagnosticsEntryAndExtra(urgency int, entry_type int, data string, extra string){
	AddDiagnosticsLog(DiagnosticsLog{Added:time.Now().Unix(),Data:data,EntryType:entry_type,Urgency:urgency, OtherData:extra})
}

func AddDiagnosticsLog(entry DiagnosticsLog){
	if entry.EntryType==0{
		panic(errors.New("Diagnostic log entries need a type"))
	}
	if len(entry.Data)==0{
		Error.Println("Refusing to add an empty diagnostics log entry")
		return
	}
	diagnosticsReceiver<-&entry
}

func StartDiagnosticsLogReceiver() {
	if gorm_db==nil{
		log.Fatal("I need gorm_db to be setup.")
	}
	go func() {
		diagnosticsReceiver = make(chan *DiagnosticsLog, 10)
		for {
			select {
			case log_entry := <-diagnosticsReceiver:
				Trace.Println("Adding entry")
				if err := gorm_db.Create(log_entry).Error; err != nil {
					Error.Print(err.Error())
				}
			}
		}
	}()
}
