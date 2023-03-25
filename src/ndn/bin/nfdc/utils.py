# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
from ...appv2 import NDNApp, pass_all
from ...security import DigestSha256Signer
from ...types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure


async def express_interest(app: NDNApp, name):
    try:
        _, data, context = await app.express(
            name, validator=pass_all, app_param=b'', signer=DigestSha256Signer(True),
            lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        return data
    except InterestNack as e:
        print(f'Nacked with reason={e.reason}')
        exit(-1)
    except InterestTimeout:
        print('Timeout')
        exit(-1)
    except InterestCanceled:
        print('Local forwarder disconnected')
        exit(-1)
    except ValidationFailure:
        print('Data failed to validate')
        exit(-1)
