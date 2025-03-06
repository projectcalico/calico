// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fv

import (
	"bufio"
	"errors"
	"fmt"
	jsontestutil "github.com/projectcalico/calico/whisker-backend/test/utils/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	gmdaemon "github.com/projectcalico/calico/goldmane/pkg/daemon"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/whisker-backend/cmd/app"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	wconfig "github.com/projectcalico/calico/whisker-backend/pkg/config"
)

func TestGoldmaneIntegration(t *testing.T) {
	ctx, teardown := setup(t)
	defer teardown()

	cfg := gmdaemon.Config{
		LogLevel:          "debug",
		Port:              5444,
		AggregationWindow: time.Second * 15,
	}

	go gmdaemon.Run(ctx, cfg)

	whiskerCfg := &wconfig.Config{
		Port:         "8080",
		LogLevel:     "debug",
		GoldmaneHost: "localhost:5444",
	}
	whiskerCfg.ConfigureLogging()

	go app.Run(ctx, whiskerCfg)

	cli, err := client.NewFlowClient("localhost:5444")
	Expect(err).ShouldNot(HaveOccurred())

	// Wait for initial connection
	<-cli.Connect(ctx)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/flows", nil)
	Expect(err).ShouldNot(HaveOccurred())

	query := req.URL.Query()
	query.Set("filters", jsontestutil.MustMarshal(t, whiskerv1.Filters{
		SourceNames: whiskerv1.FilterMatches[string]{{V: "test-source-2"}},
	}))
	query.Set("watch", "true")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)

	Expect(err).ShouldNot(HaveOccurred())

	go func() {
		<-ctx.Done()
		resp.Body.Close()
	}()

	Expect(resp.StatusCode).Should(Equal(http.StatusOK))

	scanner := newSSEScanner[whiskerv1.FlowResponse](t, resp.Body)

	cli.Push(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-source-2",
			SourceNamespace: "test-namespace-3",
			Action:          proto.Action_Deny,
		},
		StartTime: time.Now().Add(-1 * time.Second).Unix(),
		EndTime:   time.Now().Unix(),
	})

	obj, err := chanutil.ReadWithDeadline(ctx, scanner, time.Second*30)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(obj.Err).ShouldNot(HaveOccurred())
	Expect(obj.Obj.Action).Should(Equal(whiskerv1.ActionDeny))
}

type ObjWithErr[T any] struct {
	Obj T
	Err error
}

func newSSEScanner[E any](t *testing.T, r io.Reader) <-chan ObjWithErr[*E] {
	scanner := bufio.NewScanner(r)
	responseChan := make(chan ObjWithErr[*E])
	go func() {
		defer close(responseChan)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.HasPrefix(line, "data:") {
				data := strings.TrimPrefix(line, "data:")
				fmt.Println("Event Data: ", strings.TrimSpace(data))

				responseChan <- ObjWithErr[*E]{Obj: jsontestutil.MustUnmarshal[E](t, []byte(data))}
			} else {
				responseChan <- ObjWithErr[*E]{Err: errors.New(fmt.Sprintf("unexpected line: %s", line))}
			}
		}
	}()

	return responseChan
}
