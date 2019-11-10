package poplib

const (
	CommandNoop = "NOOP"
)

func Noop(c *Client) bool {
	_, err := c.WriteCmd(FormatCommand(CommandNoop), true)
	if nil != err {
		return false
	}

	return true
}
