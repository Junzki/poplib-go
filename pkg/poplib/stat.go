package poplib

type StatResult struct {
	MsgId         uint
	ContentLength uint
}


func NewStatResult(b []byte) (*StatResult, error) {
	return nil, nil
}
