package massdns

// DumpWildcardsToFile dumps the wildcard IPs list to a file.
func (instance *Instance) DumpWildcardsToFile(filename string) error {
	return instance.wildcardStore.SaveToFile(filename)
}

func (instance *Instance) LoadWildcardsFromFile(filename string) error {
	return instance.wildcardStore.LoadFromFile(filename)
}
