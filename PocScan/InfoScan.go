package PocScan

//var regEmail = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}`)

func RemoveDuplicateElement(lists []string) []string {
	result := make([]string, 0, len(lists))
	temp := map[string]struct{}{}
	for _, item := range lists {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
