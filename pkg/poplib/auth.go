package poplib

const (
	CommandUser     = "USER"
	CommandPassword = "PASS"
)

// Auth implements the plain-password authenticating method.
// C: USER <username>
// S: +OK password, please.
// C: PASS <password>
// S: +OK <and something else>
func Auth(c *Client, u, p string) error {
	logger.Infof("Auth:[%s]", u)
	userCmd := FormatCommand(CommandUser, u)
	passwdCmd := FormatCommand(CommandPassword, p)

	line, err := c.WriteCmd(userCmd, true)
	if nil != err {
		logger.Debug(err.Error())
		return err
	}

	logger.Debug(string(line))

	line, err = c.WriteCmd(passwdCmd, true)
	if nil != err {
		logger.Debug(err.Error())
		return err
	}

	logger.Debug(string(line))
	return nil
}
