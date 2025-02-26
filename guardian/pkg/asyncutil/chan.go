package asyncutil

import "context"

func ReadWithContext[S any](ctx context.Context, ch <-chan S) (S, error) {
	select {
	case <-ctx.Done():
		var d S
		return d, ctx.Err()
	case v := <-ch:
		return v, nil
	}
}

func WriteNoWait[R any](c chan R, o R) bool {
	select {
	case c <- o:
		return true
	default:
		return false
	}
}

func ReadNoWait[R any](c <-chan R) (R, bool) {
	select {
	case v := <-c:
		return v, true
	default:
		var v R
		return v, false
	}
}

func ReadBatch[R any](c <-chan R, n int) []R {
	var out []R
	for {
		select {
		case v := <-c:
			out = append(out, v)
		default:
			return out
		}

		if len(out) == n {
			return out
		}
	}
}

func ReadAll[R any](c <-chan R) []R {
	var out []R
	for {
		select {
		case v, ok := <-c:
			if !ok {
				return out
			}
			out = append(out, v)
		default:
			return out
		}
	}
}

func Clear[R any](c chan R) {
	for {
		select {
		case <-c:
		default:
			return
		}
	}
}
