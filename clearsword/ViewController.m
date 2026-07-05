#import "ViewController.h"
#import "poc.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
}

- (IBAction)go:(UIButton*)sender {
    if (!sender.enabled) {
        return;
    }

    sender.enabled = NO;
    [sender setTitle:@"running..." forState:UIControlStateDisabled];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      int result = clearsword_run();
      dispatch_async(dispatch_get_main_queue(), ^{
        [sender setTitle:(result == 0 ? @"done" : @"retry") forState:UIControlStateNormal];
        sender.enabled = YES;
      });
    });
}

@end
