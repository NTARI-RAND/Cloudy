package consumerapi

import (
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/NTARI-RAND/Cloudy/internal/market"
)

var errMarketQuery = errors.New("invalid marketplace query")

func (s *Server) parseMarketQuery(raw string) (market.ListingQuery, bool, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return market.ListingQuery{}, false, errMarketQuery
	}
	for _, name := range []string{"category", "maker", "limit", "cursor"} {
		if len(values[name]) > 1 {
			return market.ListingQuery{}, false, errMarketQuery
		}
	}
	q, err := marketFilters(values)
	if err != nil {
		return q, false, err
	}
	paged := values.Has("limit") || values.Has("cursor")
	if paged {
		q.Limit, q.Start, err = marketPageBounds(values, hx(s.logID[:]))
	}
	return q, paged, err
}

func marketFilters(values url.Values) (market.ListingQuery, error) {
	q := market.ListingQuery{Category: market.Category(values.Get("category"))}
	if q.Category != "" && !slices.Contains(market.Categories(), q.Category) {
		return q, errMarketQuery
	}
	if values.Has("maker") {
		var ok bool
		q.Maker, ok = decodeKey(values.Get("maker"))
		if !ok {
			return q, errMarketQuery
		}
	}
	for _, rail := range values["rail"] {
		switch rail {
		case "fiat":
			q.Rails.Fiat = true
		case "member_credit":
			q.Rails.MemberCredit = true
		default:
			return q, errMarketQuery
		}
	}
	return q, nil
}

func marketPageBounds(values url.Values, instance string) (int, int, error) {
	limit, start := 50, 0
	var err error
	if values.Has("limit") {
		limit, err = marketPageNumber(values.Get("limit"))
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, errMarketQuery
		}
	}
	if values.Has("cursor") {
		start, err = marketCursorPosition(values.Get("cursor"), instance)
	}
	return limit, start, err
}

func marketPageNumber(value string) (int, error) {
	if value == "" {
		return 0, errMarketQuery
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errMarketQuery
		}
	}
	n, err := strconv.Atoi(value)
	return n, err
}

func marketCursorPosition(cursor, instance string) (int, error) {
	if cursor == "0" {
		return 0, nil
	}
	prefix, position, ok := strings.Cut(cursor, ":")
	if !ok || prefix != instance {
		return 0, errMarketQuery
	}
	return marketPageNumber(position)
}
