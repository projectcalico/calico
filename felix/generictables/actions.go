package generictables

import "github.com/projectcalico/calico/felix/environment"

type ActionSet interface {
	AllowAction() Action
	DropAction() Action
	GoToAction(target string) Action
	ReturnAction() Action
	SetMarkAction(mark uint32) Action
	SetMaskedMarkAction(mark, mask uint32) Action
	ClearMarkAction(mark uint32) Action
	JumpAction(target string) Action
	NoTrackAction() Action
	LogAction(prefix string) Action
	SNATAction(ip string) Action
	DNATAction(ip string, port uint16) Action
	MasqAction(toPorts string) Action
	SetConnmarkAction(mark, mask uint32) Action
}

type Action interface {
	ToFragment(features *environment.Features) string
	String() string
}
