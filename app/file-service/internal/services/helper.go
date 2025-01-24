package services

import (
	"fmt"
	"regexp"
	"time"
)

func ParseAndFormatVersionDate(dateStr string) (string, error) {
	// Extract the components using a regular expression
	re := regexp.MustCompile(`time\.Date\((\d+), time\.([A-Za-z]+), (\d+), (\d+), (\d+), (\d+), (\d+), time\.UTC\)`)
	matches := re.FindStringSubmatch(dateStr)

	if len(matches) != 8 {
		return "", fmt.Errorf("invalid time.Date format: %s", dateStr)
	}

	// Extract the components
	year := matches[1]
	monthStr := matches[2]
	day := matches[3]
	hour := matches[4]
	minute := matches[5]
	second := matches[6]

	// Map Go month names to numeric values
	months := map[string]string{
		"January": "01", "February": "02", "March": "03", "April": "04",
		"May": "05", "June": "06", "July": "07", "August": "08",
		"September": "09", "October": "10", "November": "11", "December": "12",
	}
	month, ok := months[monthStr]
	if !ok {
		return "", fmt.Errorf("invalid month: %s", monthStr)
	}

	// Create a standard time string in RFC3339 format
	standardDate := fmt.Sprintf("%s-%s-%sT%s:%s:%sZ", year, month, day, hour, minute, second)

	// Parse the standard date string into a time.Time object
	parsedTime, err := time.Parse(time.RFC3339, standardDate)
	if err != nil {
		return "", fmt.Errorf("error parsing date: %v", err)
	}

	// Format the time into a readable format (e.g., "Jan 23, 2025 20:58:24")
	return parsedTime.Format("Jan 02, 2006 15:04:05"), nil
}
