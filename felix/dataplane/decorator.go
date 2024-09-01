// Copyright © 2024 NeuReality Ltd., and its licensors. All rights reserved.
// his software contains proprietary information of NeuReality Ltd.
// You shall use such proprietary information only as may be permitted in writing by NeuReality Ltd.
// All materials contained herein are the property of NeuReality Ltd.

// THIS SOFTWARE IS PROVIDED BY NEUREALITY “AS IS” AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL NEUREALITY OR ITS LICENSORS
// BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
// OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package dataplane

type dataplaneDriverDecorator struct {
     primaryDriver DataplaneDriver
     secondaryDriver DataplaneDriver 
}

func (decorator dataplaneDriverDecorator) SendMessage(msg interface{}) error {
     decorator.secondaryDriver.SendMessage(msg)
     return decorator.primaryDriver.SendMessage(msg) // return message from the primary driver only
}

func (decorator dataplaneDriverDecorator) RecvMessage() (msg interface{}, err error) {
     return decorator.primaryDriver.RecvMessage() // receive message from the primary driver only
}

	
