;;; Make AWS query and get responce.

;;; Copyright (c) 2009, Keiichirou SHIKANO <k16.shikano@gmail.com>
;;; All rights reserved.

;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;  
;;;    * Redistributions of source code must retain the above copyright
;;;      notice,this list of conditions and the following disclaimer.
;;;    * Redistributions in binary form must reproduce the above
;;;      copyright notice, this list of conditions and the following
;;;      disclaimer in the documentation and/or other materials provided
;;;      with the distribution.
;;;    * Neither the name of the Keiichirou SHIKANO nor the names of its
;;;      contributors may be used to endorse or promote products derived
;;;      from this software without specific prior written permission.
;;;  
;;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;; OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;; TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
;;; OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
;;; OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(define-module aws.query
  (use rfc.hmac)
  (use rfc.sha)
  (use rfc.base64)
  (use rfc.uri)
  (use srfi-19)
  (use srfi-13)
  (use rfc.http)
  (use sxml.ssax)
  (export aws:call-with-params aws:http-get aws:query-uri aws:node-prefix)
  )

(select-module aws.query)

;;; Consts
(define aws-ja        "ecs.amazonaws.jp")
(define aws-path      "/onca/xml")
(define service       "AWSECommerceService")
(define aws-version   "2009-07-01")
(define common-query-params
  `(("Service"        ,service)
    ("Version"        ,aws-version)
    ))

;;; [(QueryKey Value)] -> QueryKey1=Value1&QueryKey2=Value2&...
(define (params-join . ps)
  (string-join 
   (sort (map (cut string-join <> "=")
	      (map (lambda (p) 
		     (list (car p) (upcase-uri-encode-string (cadr p))))
		   (fold cons common-query-params ps))))
   "&"))

;;; HMAC SHA256 Signature
(define (calc-signature str seckey)
  (uri-encode-string
   (base64-encode-string 
    (hmac-digest-string str :key seckey :hasher <sha256>))))

(define (upcase-uri-encode-string str)
  (regexp-replace-all #/%[0-9a-f]{2}/ (uri-encode-string str) 
		      (lambda (m) (string-upcase (m)))))

(define (to-sign-str params-str)
   (string-join
    (list
     "GET"
     aws-ja
     aws-path
     params-str)
    "\n"))

;;; Make AWS Query
(define (aws:query-uri seckey . args)
  (define (timestamp)
    `("Timestamp" ,(date->string (current-date) "~4")))
  (let-keywords* args ((params '()))
    (let1 params-str (apply params-join (cons (timestamp) params))
      (string-append aws-path "?"
		     params-str "&"
		     "Signature=" (calc-signature (to-sign-str params-str) seckey)))))

;;; Get from AWS
(define (aws:node-prefix node)
  (define prefix-str "http://webservices.amazon.com/AWSECommerceService/2009-07-01:")
  (string->symbol (string-append  prefix-str (x->string node))))

(define (aws:http-get seckey . args)
  (let-keywords* args ((proxy #f) (params '()))
    (let1 uri (aws:query-uri seckey :params params)
      (if proxy
	  (http-get proxy (string-append "http://" aws-ja uri))
	  (http-get aws-ja uri)))))

(define (aws:call-with-params seckey proc . args)
  ;; proc :: sxml -> result
  (let-keywords* args ((proxy #f) (params '()))
    (receive (responce-code header body)
	     (aws:http-get seckey :proxy proxy :params params)
	     (call-with-input-string 
	      body
	      (lambda (p) 
		(proc (ssax:xml->sxml p '())))))))

(provide "aws/query")
