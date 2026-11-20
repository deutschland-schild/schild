package logcheck

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// HumanSize formats bytes as B, KiB or MiB.
func HumanSize(n int64) string {
	switch {
	case n >= mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/mib)
	case n >= 1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	}
	return fmt.Sprintf("%d B", n)
}

var catLabel = map[string]string{
	CatBodyTooLarge: "body above limit",
	CatBodyEncoding: "compressed request body",
	CatTooManyArgs:  "> 1000 query arguments",
	CatLongParam:    "long query value (timeout risk)",
	CatLargeForm:    "large urlencoded form (timeout risk)",
}

// WriteText writes the human-readable report.
func WriteText(w io.Writer, rep *Report) error {
	fmt.Fprintf(w, "schild logcheck - limits: body %d bytes (%s), %d query arguments, eval timeout %d ms [%s]\n",
		rep.Limits.BodyBytes, HumanSize(rep.Limits.BodyBytes), rep.Limits.Args, rep.Limits.EvalTimeoutMS, rep.Limits.Source)
	for _, s := range rep.Sites {
		fmt.Fprintf(w, "\n== site %s ==\n", s.Site)
		period := "unknown"
		if s.From != "" {
			period = s.From + " .. " + s.To
		}
		fmt.Fprintf(w, "requests %d (unparsed lines %d), period %s, formats %v\n", s.Records, s.Unparsed, period, s.Formats)
		for _, e := range s.UnparsedEx {
			fmt.Fprintf(w, "  unparsed: %s\n", e)
		}
		fmt.Fprintf(w, "coverage: body size known %d, request_length only %d, Content-Encoding logged %d\n",
			s.Coverage.BodySizeKnown, s.Coverage.RequestLengthOnly, s.Coverage.ContentEncodingLog)
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "CHECK\tSTATUS\tCERTAIN\tPOSSIBLE\tMAX\tEXAMPLE PATHS")
		if len(s.Findings) == 0 {
			fmt.Fprintln(tw, "(none)\t-\t0\t0\t-\t-")
		}
		for _, f := range s.Findings {
			var ex []string
			for _, e := range f.Examples {
				x := fmt.Sprintf("%s (%d)", e.Path, e.Count)
				if len(e.IPs) > 0 {
					x += " [" + strings.Join(e.IPs, " ") + "]"
				}
				ex = append(ex, x)
			}
			maxv := HumanSize(f.MaxValue)
			if f.Category == CatTooManyArgs {
				maxv = fmt.Sprintf("%d args", f.MaxValue)
			} else if f.Category == CatBodyEncoding && f.MaxValue == 0 {
				maxv = "-"
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\n", catLabel[f.Category], f.Status, f.Certain, f.Possible, maxv, strings.Join(ex, ", "))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		z := s.Sizes
		fmt.Fprintf(w, "body sizes (%d with body, %d empty): p50 %s, p90 %s, p99 %s, p99.9 %s, max %s\n",
			z.Known-z.Empty, z.Empty, HumanSize(z.P50), HumanSize(z.P90), HumanSize(z.P99), HumanSize(z.P999), HumanSize(z.Max))
		var bs []string
		for _, b := range z.Buckets {
			bs = append(bs, fmt.Sprintf("%s: %d", b.Bucket, b.Count))
		}
		fmt.Fprintf(w, "  %s\n", strings.Join(bs, " | "))
		if z.RLMax > 0 {
			fmt.Fprintf(w, "  largest request_length without a body size: %s\n", HumanSize(z.RLMax))
		}
		fmt.Fprintf(w, "query: max %d arguments, longest value %s\n", s.Query.MaxArgs, HumanSize(int64(s.Query.MaxParamLength)))
		if len(s.AppStatuses) > 0 {
			fmt.Fprintf(w, "baseline, answered by the application itself: %v\n", s.AppStatuses)
		}
		fmt.Fprintf(w, "suggested schild.yaml: waf.request_body_limit_bytes: %d   waf.eval_timeout_ms: %d\n",
			s.Suggest.RequestBodyLimitBytes, s.Suggest.EvalTimeoutMS)
		for _, n := range s.Suggest.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
	fmt.Fprintln(w)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	return nil
}
